const fs = require("fs-extra");
const path = require("path");
const { XMLParser } = require("fast-xml-parser");
const { DANGEROUS_PERMISSIONS } = require("./permissions");

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
 * Parses <output>/apktool/AndroidManifest.xml (apktool's decompiled, human-readable
 * manifest) into a structured summary: package info, SDK levels, permissions
 * (flagged by risk), and exported components.
 */
async function parseManifest(apktoolOutDir) {
  const manifestPath = path.join(apktoolOutDir, "AndroidManifest.xml");
  if (!(await fs.pathExists(manifestPath))) {
    throw new Error(`AndroidManifest.xml not found at ${manifestPath} — did the apktool step run successfully?`);
  }

  const xml = await fs.readFile(manifestPath, "utf8");
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "" });
  const parsed = parser.parse(xml);

  const manifestNode = parsed.manifest || {};
  const appNode = manifestNode.application || {};

  const packageName = manifestNode.package;
  const versionCode = manifestNode[`${ANDROID_NS}versionCode`];
  const versionName = manifestNode[`${ANDROID_NS}versionName`];

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
    }));

  function summarizeComponents(kind) {
    return arr(appNode[kind]).map((c) => ({
      name: attr(c, "name"),
      exported: attr(c, "exported") === "true",
      hasIntentFilter: Boolean(c && c["intent-filter"]),
    }));
  }

  const components = {
    activities: summarizeComponents("activity"),
    services: summarizeComponents("service"),
    receivers: summarizeComponents("receiver"),
    providers: summarizeComponents("provider"),
  };

  // Components explicitly exported, OR implicitly exported by having an
  // intent-filter without an explicit exported="false" — a very common
  // real-world misconfiguration worth flagging.
  const flaggedExported = [];
  for (const [kind, list] of Object.entries(components)) {
    for (const c of list) {
      if (c.exported || (c.hasIntentFilter && c.exported !== false)) {
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
    permissions,
    dangerousPermissions: permissions.filter((p) => p.dangerous).map((p) => p.name),
    components,
    flaggedExported,
  };
}

module.exports = { parseManifest };
