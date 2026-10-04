/**
 * Turns the raw list of URLs found in decompiled sources into something a
 * reviewer can act on: which hosts the app talks to, which use plain HTTP,
 * which are raw IPs, and which point at cloud storage / database endpoints
 * that are commonly misconfigured.
 */

// XML namespaces, license headers and spec URLs that show up in nearly every
// decompiled app. They're still listed in `urls`, but never flagged.
const NOISE_HOSTS = new Set([
  "schemas.android.com",
  "schemas.xmlsoap.org",
  "schemas.microsoft.com",
  "www.w3.org",
  "w3.org",
  "www.apache.org",
  "apache.org",
  "xmlpull.org",
  "www.xmlpull.org",
  "xml.org",
  "java.sun.com",
  "ns.adobe.com",
]);

// Local/emulator addresses — plain HTTP or raw IPs here aren't a finding.
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "10.0.2.2", "10.0.3.2", "[::1]"]);

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

const NOTABLE = [
  { kind: "firebase-realtime-db", test: (h) => h.endsWith(".firebaseio.com") || h.endsWith(".firebasedatabase.app") },
  { kind: "aws-s3-bucket", test: (h) => /(^|\.)s3([.-][a-z0-9-]+)?\.amazonaws\.com$/.test(h) },
  { kind: "gcs-bucket", test: (h) => h === "storage.googleapis.com" || h.endsWith(".storage.googleapis.com") },
  { kind: "azure-blob-storage", test: (h) => h.endsWith(".blob.core.windows.net") },
];

function safeParse(u) {
  try {
    return new URL(u);
  } catch {
    return null;
  }
}

/**
 * @param {string[]} urls
 * @param {{ topDomains?: number, maxListed?: number }} [opts]
 */
function analyzeUrls(urls, { topDomains = 25, maxListed = 50 } = {}) {
  const hostCounts = new Map();
  const cleartext = [];
  const ipUrls = [];
  const notable = [];
  const seenNotable = new Set();

  for (const u of urls) {
    const parsed = safeParse(u);
    if (!parsed) continue;
    const host = parsed.hostname.toLowerCase();
    if (!host || NOISE_HOSTS.has(host)) continue;

    hostCounts.set(host, (hostCounts.get(host) || 0) + 1);
    if (LOCAL_HOSTS.has(host)) continue;

    if (parsed.protocol === "http:") cleartext.push(u);
    if (IPV4.test(host)) ipUrls.push(u);

    for (const { kind, test } of NOTABLE) {
      if (test(host)) {
        const key = `${kind}::${host}`;
        if (!seenNotable.has(key)) {
          seenNotable.add(key);
          notable.push({ kind, host, url: u });
        }
        break;
      }
    }
  }

  const domains = Array.from(hostCounts, ([host, count]) => ({ host, count }))
    .sort((a, b) => b.count - a.count || a.host.localeCompare(b.host))
    .slice(0, topDomains);

  return {
    domains,
    cleartextUrls: cleartext.slice(0, maxListed),
    cleartextTotal: cleartext.length,
    ipUrls: ipUrls.slice(0, maxListed),
    ipTotal: ipUrls.length,
    notable,
  };
}

module.exports = { analyzeUrls, NOISE_HOSTS };
