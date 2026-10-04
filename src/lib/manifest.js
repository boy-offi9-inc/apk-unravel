const fs = require("fs-extra");
const path = require("path");
const { XMLParser } = require("fast-xml-parser");
const { DANGEROUS_PERMISSIONS, permissionTier } = require("./permissions");
const { parseNetworkSecurityConfig } = require("./networkSecurity");

const ANDROID_NS = "android:";

function arr(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

function attr(node, name) {
  if (!node) return undefined;
  return node[`${ANDROID_NS}${name}`];
}

/**
 * Parses the decoded AndroidManifest.xml in the given directory (apktool's output
 * root, or <jadx out>/resources under --jadx-only) into a structured summary: package info, SDK levels, permissions
 * (flagged by risk), and exported components.
 */
async function parseManifest(apktoolOutDir) {
  const manifestPath = path.join(apktoolOutDir, "AndroidManifest.xml");
  if (!(await fs.pathExists(manifestPath))) {
    throw new Error(`AndroidManifest.xml not found at ${manifestPath} — did the apktool/jadx decompile step run successfully?`);
  }

  const xml = await fs.readFile(manifestPath, "utf8");
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "" });
  const parsed = parser.parse(xml);

  const manifestNode = parsed.manifest || {};
  const appNode = manifestNode.application || {};

  const packageName = manifestNode.package;
  const versionCode = manifestNode[`${ANDROID_NS}versionCode`];
  const versionName = manifestNode[`${ANDROID_NS}versionName`];

  // Raw label/icon refs off <application> — these are often resource
  // references like "@string/app_name" / "@mipmap/ic_launcher" rather than
  // literal values, so resolving them to an actual name/file needs the res/
  // folder too. That resolution lives in appIdentity.js; we just capture the
  // raw refs here since this function only reads the manifest.
  const appLabelRef = attr(appNode, "label");
  const appIconRef = attr(appNode, "icon");

  const usesSdk = manifestNode["uses-sdk"] || {};
  const minSdk = attr(usesSdk, "minSdkVersion");
  const targetSdk = attr(usesSdk, "targetSdkVersion");

  const permissionNodes = arr(manifestNode["uses-permission"]).concat(
    arr(manifestNode["uses-permission-sdk-23"])
  );
  const permissions = permissionNodes
    .map((p) => attr(p, "name"))
    .filter(Boolean)
    .map((name) => ({
      name,
      dangerous: DANGEROUS_PERMISSIONS.has(name),
      tier: permissionTier(name),
    }));

  /**
   * Extracts scheme/host/path combos declared on a component's <intent-filter>
   * <data> tags — i.e. the actual custom URI schemes / deep links / App Links
   * that can reach this component from outside the app. This is the concrete
   * detail behind "flagged exported" that matters for deep-link-hijacking
   * style analysis: knowing *that* something is exported is one thing,
   * knowing *what URI opens it* is what an attacker (or a reviewer) needs.
   */
  function extractDeepLinks(c) {
    const filters = arr(c["intent-filter"]);
    const links = [];
    for (const filter of filters) {
      const dataEntries = arr(filter.data);
      for (const d of dataEntries) {
        const scheme = attr(d, "scheme");
        const host = attr(d, "host");
        const path = attr(d, "path") || attr(d, "pathPrefix") || attr(d, "pathPattern");
        const mimeType = attr(d, "mimeType");
        if (scheme || host || path || mimeType) {
          links.push({ scheme: scheme || null, host: host || null, path: path || null, mimeType: mimeType || null });
        }
      }
    }
    return links;
  }

  // A permission this manifest declares itself with protectionLevel "normal"
  // (or none — which defaults to normal) is granted to any app that asks, so
  // guarding a component with it isn't real protection.
  const customPermissions = arr(manifestNode.permission)
    .map((p) => ({ name: attr(p, "name"), protectionLevel: attr(p, "protectionLevel") || "normal" }))
    .filter((p) => p.name);
  const weakPermissionNames = new Set(customPermissions.filter((p) => p.protectionLevel === "normal").map((p) => p.name));

  function isLauncherFilter(filter) {
    const actions = arr(filter.action).map((a) => attr(a, "name"));
    const categories = arr(filter.category).map((c) => attr(c, "name"));
    return actions.includes("android.intent.action.MAIN") && categories.includes("android.intent.category.LAUNCHER");
  }

  function summarizeComponents(tag) {
    return arr(appNode[tag]).map((c) => {
      const rawExported = attr(c, "exported");
      const filters = arr(c && c["intent-filter"]);
      const permission = attr(c, "permission") || null;
      const readPermission = attr(c, "readPermission") || null;
      const writePermission = attr(c, "writePermission") || null;
      // A provider is only guarded when *both* directions are; a single
      // permission attribute covers both.
      const guardNames = permission ? [permission] : readPermission && writePermission ? [readPermission, writePermission] : [];
      return {
        name: attr(c, "name"),
        exported: rawExported === "true",
        exportedExplicitlyFalse: rawExported === "false",
        hasIntentFilter: Boolean(c && c["intent-filter"]),
        deepLinks: extractDeepLinks(c),
        permission: guardNames.length ? guardNames.join(" + ") : null,
        guarded: guardNames.length > 0,
        weakGuard: guardNames.length > 0 && guardNames.every((n) => weakPermissionNames.has(n)),
        launcher: filters.some(isLauncherFilter),
        targetActivity: tag === "activity-alias" ? attr(c, "targetActivity") || null : undefined,
      };
    });
  }

  const components = {
    activities: summarizeComponents("activity"),
    activityAliases: summarizeComponents("activity-alias"),
    services: summarizeComponents("service"),
    receivers: summarizeComponents("receiver"),
    providers: summarizeComponents("provider"),
  };

  // Flattened, top-level view of every deep link found on any component —
  // convenient for reporting without having to walk all four component
  // arrays again. Each entry keeps a reference back to the component it
  // came from and whether that component is actually reachable (exported).
  const deepLinks = [];
  for (const [kind, list] of Object.entries(components)) {
    for (const c of list) {
      if (!c.deepLinks.length) continue;
      const reachable = c.exported || (c.hasIntentFilter && !c.exportedExplicitlyFalse);
      for (const link of c.deepLinks) {
        deepLinks.push({ kind, component: c.name, reachable, ...link });
      }
    }
  }

  // Application-level security flags — common, cheap-to-check misconfigurations
  // that are worth surfacing in any static-analysis pass.
  const debuggable = attr(appNode, "debuggable") === "true";
  const allowBackupRaw = attr(appNode, "allowBackup");
  // allowBackup defaults to true when the attribute is absent, so treat
  // "absent" the same as "true" for flagging purposes.
  const allowBackup = allowBackupRaw !== "false";
  const usesCleartextTrafficRaw = attr(appNode, "usesCleartextTraffic");
  // Cleartext traffic defaults to allowed below targetSdk 28, and disallowed
  // from 28 onward — only flag it when the manifest *explicitly* opts in,
  // since an absent attribute's real default depends on targetSdk.
  const usesCleartextTraffic = usesCleartextTrafficRaw === "true";
  const networkSecurityConfig = attr(appNode, "networkSecurityConfig") || null;
  const testOnly = attr(appNode, "testOnly") === "true";
  const sharedUserId = manifestNode[`${ANDROID_NS}sharedUserId`] || null;
  const networkSecurityDetails = await parseNetworkSecurityConfig(apktoolOutDir, networkSecurityConfig);

  const securityFlags = [];
  if (debuggable) {
    securityFlags.push({
      flag: "debuggable",
      severity: "high",
      detail: 'android:debuggable="true" — app is debuggable; should never ship in a production build.',
    });
  }
  if (allowBackup) {
    securityFlags.push({
      flag: "allowBackup",
      severity: "medium",
      detail:
        allowBackupRaw === undefined
          ? 'android:allowBackup not set (defaults to true) — app data may be extractable via "adb backup" on debuggable devices.'
          : 'android:allowBackup="true" — app data may be extractable via "adb backup" on debuggable devices.',
    });
  }
  if (usesCleartextTraffic) {
    securityFlags.push({
      flag: "usesCleartextTraffic",
      severity: "medium",
      detail: 'android:usesCleartextTraffic="true" — app explicitly allows unencrypted HTTP traffic.',
    });
  }

  if (testOnly) {
    securityFlags.push({
      flag: "testOnly",
      severity: "medium",
      detail: 'android:testOnly="true" — build is marked test-only (installable only via "adb install -t"); not a production build.',
    });
  }
  if (sharedUserId) {
    securityFlags.push({
      flag: "sharedUserId",
      severity: "low",
      detail: `android:sharedUserId="${sharedUserId}" — shares a Linux UID with other apps signed by the same key (deprecated since API 29); a compromise of one app exposes the others' data.`,
    });
  }

  if (networkSecurityDetails && networkSecurityDetails.found) {
    const nsc = networkSecurityDetails;
    if (nsc.baseCleartextPermitted === true) {
      securityFlags.push({
        flag: "networkSecurityConfigCleartext",
        severity: "medium",
        detail: "network_security_config base-config permits cleartext (HTTP) traffic for every domain.",
      });
    }
    const cleartextDomains = nsc.domainConfigs.filter((d) => d.cleartextPermitted === true).flatMap((d) => d.domains);
    if (cleartextDomains.length) {
      securityFlags.push({
        flag: "networkSecurityConfigCleartextDomains",
        severity: "low",
        detail: `network_security_config permits cleartext traffic to: ${cleartextDomains.join(", ")}.`,
      });
    }
    if (nsc.trustsUserCertificates || nsc.domainConfigs.some((d) => d.trustsUserCertificates)) {
      securityFlags.push({
        flag: "trustsUserCertificates",
        severity: "medium",
        detail: "network_security_config trusts user-installed CA certificates outside debug-overrides — TLS interception (e.g. a proxy CA) works against this app in production.",
      });
    }
  } else if (networkSecurityDetails && !networkSecurityDetails.found) {
    securityFlags.push({
      flag: "networkSecurityConfigUnreadable",
      severity: "info",
      detail: `android:networkSecurityConfig="${networkSecurityDetails.ref}" is referenced but the file could not be read/parsed — review it manually.`,
    });
  }

  const security = {
    debuggable,
    allowBackup,
    usesCleartextTraffic,
    networkSecurityConfig,
    networkSecurity: networkSecurityDetails,
    testOnly,
    sharedUserId,
    flags: securityFlags,
  };

  // Components explicitly exported, OR implicitly exported by having an
  // intent-filter without an explicit exported="false" — a very common
  // real-world misconfiguration worth flagging.
  const flaggedExported = [];
  for (const [kind, list] of Object.entries(components)) {
    for (const c of list) {
      const implicit = !c.exported && c.hasIntentFilter && !c.exportedExplicitlyFalse;
      if (c.exported || implicit) {
        flaggedExported.push({
          kind,
          name: c.name,
          exposedVia: c.exported ? "exported=true" : "intent-filter",
          permission: c.permission,
          guarded: c.guarded,
          weakGuard: c.weakGuard,
          launcher: c.launcher,
        });
      }
    }
  }
  // The launcher entry point is *supposed* to be reachable, so it isn't part
  // of the "worth a manual look" count — but it stays listed in flaggedExported.
  const unguardedExported = flaggedExported.filter((c) => (!c.guarded || c.weakGuard) && !c.launcher);

  return {
    packageName,
    versionCode,
    versionName,
    minSdk,
    targetSdk,
    appLabelRef,
    appIconRef,
    permissions,
    dangerousPermissions: permissions.filter((p) => p.dangerous).map((p) => p.name),
    components,
    flaggedExported,
    unguardedExported,
    customPermissions,
    deepLinks,
    security,
  };
}

module.exports = { parseManifest };
