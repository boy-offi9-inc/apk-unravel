const fs = require("fs-extra");
const path = require("path");
const { XMLParser } = require("fast-xml-parser");
const { DANGEROUS_PERMISSIONS, permissionTier } = require("./permissions");

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

  function summarizeComponents(kind) {
    return arr(appNode[kind]).map((c) => {
      const rawExported = attr(c, "exported");
      return {
        name: attr(c, "name"),
        exported: rawExported === "true",
        exportedExplicitlyFalse: rawExported === "false",
        hasIntentFilter: Boolean(c && c["intent-filter"]),
        deepLinks: extractDeepLinks(c),
      };
    });
  }

  const components = {
    activities: summarizeComponents("activity"),
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

  const security = {
    debuggable,
    allowBackup,
    usesCleartextTraffic,
    networkSecurityConfig,
    flags: securityFlags,
  };

  // Components explicitly exported, OR implicitly exported by having an
  // intent-filter without an explicit exported="false" — a very common
  // real-world misconfiguration worth flagging.
  const flaggedExported = [];
  for (const [kind, list] of Object.entries(components)) {
    for (const c of list) {
      if (c.exported || (c.hasIntentFilter && !c.exportedExplicitlyFalse)) {
        flaggedExported.push({ kind, name: c.name });
      }
    }
  }

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
    deepLinks,
    security,
  };
}

module.exports = { parseManifest };
