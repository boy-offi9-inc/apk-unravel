const fs = require("fs-extra");
const path = require("path");

const URL_REGEX = /https?:\/\/[^\s"'<>)]+/g;

// Deliberately generic/high-level patterns for common secret shapes. This is a
// best-effort heuristic scan (like many static-analysis tools ship), not a
// guarantee — always confirm findings before treating them as sensitive.
const SECRET_PATTERNS = [
  { label: "Generic API key assignment", regex: /['"]?api[_-]?key['"]?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi },
  { label: "AWS Access Key ID", regex: /AKIA[0-9A-Z]{16}/g },
  { label: "Google API key", regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { label: "Firebase/Bearer-style long token", regex: /['"]?(?:token|secret|bearer)['"]?\s*[:=]\s*['"][A-Za-z0-9_\-.]{20,}['"]/gi },
];

const SCAN_EXTENSIONS = new Set([".java", ".xml", ".smali", ".json", ".txt"]);
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // skip anything absurdly large (compiled blobs etc.)

/**
 * Walks a decompiled output directory and collects unique URLs and
 * potential-secret matches. Intended as a quick informational pass, not
 * a substitute for a real security review.
 */
async function scanStrings(rootDir, { maxMatchesPerCategory = 200 } = {}) {
  const urls = new Set();
  const secrets = [];

  async function walk(dir) {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
        continue;
      }
      if (!SCAN_EXTENSIONS.has(path.extname(entry.name))) continue;

      let stat;
      try {
        stat = await fs.stat(full);
      } catch {
        continue;
      }
      if (stat.size > MAX_FILE_SIZE_BYTES) continue;

      let content;
      try {
        content = await fs.readFile(full, "utf8");
      } catch {
        continue;
      }

      const urlMatches = content.match(URL_REGEX) || [];
      for (const u of urlMatches) {
        if (urls.size < maxMatchesPerCategory) urls.add(u);
      }

      for (const { label, regex } of SECRET_PATTERNS) {
        const matches = content.match(regex) || [];
        for (const m of matches) {
          if (secrets.length < maxMatchesPerCategory) {
            secrets.push({ label, match: m, file: path.relative(rootDir, full) });
          }
        }
      }
    }
  }

  await walk(rootDir);

  return {
    urls: Array.from(urls),
    potentialSecrets: secrets,
  };
}

module.exports = { scanStrings };
