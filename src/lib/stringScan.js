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
  { label: "Private key block", regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { label: "Slack token", regex: /xox[baprs]-[A-Za-z0-9-]{10,48}/g },
  { label: "Stripe live secret key", regex: /sk_live_[A-Za-z0-9]{16,}/g },
  { label: "JWT", regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
];

// Matches captured entirely against known placeholder/example wording get
// dropped — "YOUR_API_KEY_HERE" satisfies the generic 16+ char pattern but
// isn't a real credential, and flagging it just trains people to ignore the
// scan's output.
const PLACEHOLDER_REGEX = /YOUR[_-]?API|PLACEHOLDER|EXAMPLE|SAMPLE|CHANGE[_-]?ME|INSERT[_-]?KEY|DUMMY|XXXX|TEST[_-]?KEY|FAKE[_-]?KEY|AKIAIOSFODNN7EXAMPLE/i;

const SCAN_EXTENSIONS = new Set([
  ".java",
  ".kt",
  ".xml",
  ".smali",
  ".json",
  ".txt",
  ".properties",
  ".yml",
  ".yaml",
  ".js",
  ".html",
]);
const MAX_FILE_SIZE_BYTES = 4 * 1024 * 1024; // skip anything absurdly large (compiled blobs, bundled JS, etc.)
const MAX_FILES_PER_SECRET = 5; // cap how many source files we list per unique secret

/**
 * Masks a matched secret for safe display in the human-readable report —
 * keeps a few characters at each end so a reviewer can still recognize which
 * credential it is without the full value sitting in plaintext in report.md
 * (which people commonly commit or share). report.json keeps the full match
 * for anyone actually running this against their own app and needing to act
 * on the finding.
 */
function maskSecret(value) {
  if (value.length <= 12) return value.slice(0, 2) + "…" + value.slice(-2);
  return value.slice(0, 6) + "…" + value.slice(-4);
}

/**
 * Compiles one raw --grep keyword into a regex. Two forms are supported:
 *   - /pattern/flags — used as a real regex (flags default to case-sensitive
 *     unless "i" is given; "g" is always forced on so we can find every hit)
 *   - anything else — treated as a plain, case-insensitive literal substring
 *     search, with regex metacharacters escaped so e.g. "api.example.com"
 *     doesn't accidentally become a wildcard pattern.
 * Invalid regex syntax is reported back via `error` instead of throwing, so
 * one bad --grep term doesn't abort the whole scan.
 */
function compileKeyword(raw) {
  const regexForm = raw.match(/^\/(.+)\/([a-z]*)$/i);
  if (regexForm) {
    const [, pattern, flags] = regexForm;
    const finalFlags = flags.includes("g") ? flags : flags + "g";
    try {
      return { keyword: raw, regex: new RegExp(pattern, finalFlags) };
    } catch (err) {
      return { keyword: raw, error: err.message };
    }
  }
  const escaped = raw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return { keyword: raw, regex: new RegExp(escaped, "gi") };
}

/**
 * Splits a --grep CLI value ("firebase,MyCo,/api\.foo\.[a-z]+/i") into
 * compiled keyword matchers, separating out any that failed to compile so
 * the caller can warn about them without losing the valid ones.
 */
function parseKeywords(rawValue) {
  if (!rawValue) return { compiled: [], invalid: [] };
  const parts = rawValue
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const compiled = [];
  const invalid = [];
  for (const part of parts) {
    const result = compileKeyword(part);
    if (result.error) invalid.push({ keyword: result.keyword, error: result.error });
    else compiled.push(result);
  }
  return { compiled, invalid };
}

/**
 * Walks a decompiled output directory and collects unique URLs,
 * potential-secret matches, and (if given) custom keyword/regex matches.
 * Intended as a quick informational pass, not a substitute for a real
 * security review.
 *
 * Secrets (and keyword matches) are deduplicated by (label, matched value) —
 * smali re-embeds the literal value of a string constant at every call site
 * that references it, so without dedup a single real match can flood the
 * report as dozens of near-identical rows. Each unique finding instead lists
 * the (capped) set of files it was seen in plus a total occurrence count.
 *
 * @param {string} rootDir
 * @param {object} [opts]
 * @param {number} [opts.maxMatchesPerCategory=200]
 * @param {string[]} [opts.keywords] - already-compiled keyword matchers from
 *   parseKeywords().compiled — kept as a separate step so the CLI can surface
 *   `invalid` entries before the scan even starts.
 */
async function scanStrings(rootDir, { maxMatchesPerCategory = 200, keywords = [] } = {}) {
  const urls = new Set();
  const secretsByKey = new Map();
  const keywordsByKey = new Map();

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

      const relFile = path.relative(rootDir, full);
      for (const { label, regex } of SECRET_PATTERNS) {
        const matches = content.match(regex) || [];
        for (const m of matches) {
          if (PLACEHOLDER_REGEX.test(m)) continue;

          const key = `${label}::${m}`;
          let entryRec = secretsByKey.get(key);
          if (!entryRec) {
            if (secretsByKey.size >= maxMatchesPerCategory) continue;
            entryRec = { label, match: m, masked: maskSecret(m), files: new Set(), occurrences: 0 };
            secretsByKey.set(key, entryRec);
          }
          entryRec.occurrences++;
          if (entryRec.files.size < MAX_FILES_PER_SECRET) entryRec.files.add(relFile);
        }
      }

      for (const { keyword, regex } of keywords) {
        const matches = content.match(regex) || [];
        for (const m of matches) {
          const key = `${keyword}::${m}`;
          let entryRec = keywordsByKey.get(key);
          if (!entryRec) {
            if (keywordsByKey.size >= maxMatchesPerCategory) continue;
            entryRec = { keyword, match: m, files: new Set(), occurrences: 0 };
            keywordsByKey.set(key, entryRec);
          }
          entryRec.occurrences++;
          if (entryRec.files.size < MAX_FILES_PER_SECRET) entryRec.files.add(relFile);
        }
      }
    }
  }

  await walk(rootDir);

  const potentialSecrets = Array.from(secretsByKey.values()).map((s) => ({
    label: s.label,
    match: s.match,
    masked: s.masked,
    occurrences: s.occurrences,
    files: Array.from(s.files),
    truncatedFileList: s.occurrences > s.files.size || s.files.size >= MAX_FILES_PER_SECRET,
  }));

  const keywordMatches = Array.from(keywordsByKey.values()).map((k) => ({
    keyword: k.keyword,
    match: k.match,
    occurrences: k.occurrences,
    files: Array.from(k.files),
    truncatedFileList: k.occurrences > k.files.size || k.files.size >= MAX_FILES_PER_SECRET,
  }));

  return {
    urls: Array.from(urls),
    potentialSecrets,
    keywordMatches,
  };
}

module.exports = { scanStrings, parseKeywords };
