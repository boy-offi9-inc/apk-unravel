const fs = require("fs-extra");
const path = require("path");
const { XMLParser } = require("fast-xml-parser");

function arr(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

const isTrue = (v) => String(v).toLowerCase() === "true";

function domainText(d) {
  if (d && typeof d === "object") return String(d["#text"] ?? "").trim();
  return String(d ?? "").trim();
}

function trustsUserCerts(cfg) {
  const anchors = arr(cfg?.["trust-anchors"]);
  return anchors.some((a) => arr(a?.certificates).some((c) => c?.src === "user"));
}

/**
 * Parses the app's network security config (res/xml/<name>.xml, referenced
 * from <application android:networkSecurityConfig="@xml/name">) into the
 * handful of facts that matter for a transport-security review.
 *
 * @param {string} resourceRoot - dir containing res/ (apktool output root, or <jadx>/resources)
 * @param {string} ref - raw manifest reference, e.g. "@xml/network_security_config"
 * @returns {Promise<null | object>} null when nothing is referenced; otherwise
 *   { ref, found, ... }. found:false means the file couldn't be located/parsed.
 */
async function parseNetworkSecurityConfig(resourceRoot, ref) {
  if (!ref) return null;
  const m = /^@xml\/(.+)$/.exec(ref);
  const result = {
    ref,
    found: false,
    baseCleartextPermitted: null,
    trustsUserCertificates: false,
    domainConfigs: [],
    hasPinning: false,
    hasDebugOverrides: false,
  };
  if (!m) return result;

  const file = path.join(resourceRoot, "res", "xml", `${m[1]}.xml`);
  if (!(await fs.pathExists(file))) return result;

  let parsed;
  try {
    parsed = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "" }).parse(await fs.readFile(file, "utf8"));
  } catch {
    return result;
  }
  const root = parsed["network-security-config"];
  if (!root || typeof root !== "object") return result;
  result.found = true;

  const base = arr(root["base-config"])[0];
  if (base && typeof base === "object") {
    if (base.cleartextTrafficPermitted !== undefined) result.baseCleartextPermitted = isTrue(base.cleartextTrafficPermitted);
    result.trustsUserCertificates = trustsUserCerts(base);
  }

  const collect = (node, nested) => {
    for (const dc of arr(node?.["domain-config"])) {
      const domains = arr(dc?.domain).map(domainText).filter(Boolean);
      result.domainConfigs.push({
        domains,
        cleartextPermitted: dc?.cleartextTrafficPermitted === undefined ? null : isTrue(dc.cleartextTrafficPermitted),
        trustsUserCertificates: trustsUserCerts(dc),
        pinned: Boolean(dc?.["pin-set"]),
      });
      if (dc?.["pin-set"]) result.hasPinning = true;
      collect(dc, true); // domain-configs may be nested
    }
  };
  collect(root, false);

  result.hasDebugOverrides = Boolean(root["debug-overrides"]);
  return result;
}

module.exports = { parseNetworkSecurityConfig };
