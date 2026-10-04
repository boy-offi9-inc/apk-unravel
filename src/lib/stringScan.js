const fs = require("fs-extra");
const path = require("path");
const { analyzeUrls } = require("./urlAnalysis");

const URL_REGEX = /https?:\/\/[^\s"'<>)]+/g;

// Deliberately generic/high-level patterns for common secret shapes. This is a
// best-effort heuristic scan (like many static-analysis tools ship), not a
// guarantee — always confirm findings before treating them as sensitive.
//
// Patterns with `generic: true` match any long quoted value after a name like
// api_key/token/secret, so they also pass an entropy check (see looksRandom) —
// otherwise identifiers such as "authorization_token_header" get flagged.
const SECRET_PATTERNS = [
  { label: "Generic API key assignment", generic: true, regex: /['"]?api[_-]?key['"]?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/gi },
  { label: "Firebase/Bearer-style long token", generic: true, regex: /['"]?(?:token|secret|bearer)['"]?\s*[:=]\s*['"][A-Za-z0-9_\-.]{20,}['"]/gi },
  { label: "AWS Access Key ID", regex: /AKIA[0-9A-Z]{16}/g },
  { label: "AWS secret access key assignment", generic: true, regex: /aws[\w.-]{0,20}secret[\w.-]{0,20}['"]\s*[:=,]?\s*['"][A-Za-z0-9\/+=]{40}['"]/gi },
  { label: "Google API key", regex: /AIza[0-9A-Za-z\-_]{35}/g },
  { label: "Private key block", regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { label: "Slack token", regex: /xox[baprs]-[A-Za-z0-9-]{10,48}/g },
  { label: "Slack webhook URL", regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g },
  { label: "Stripe live secret key", regex: /sk_live_[A-Za-z0-9]{16,}/g },
  { label: "Stripe live restricted key", regex: /rk_live_[A-Za-z0-9]{16,}/g },
  { label: "GitHub token", regex: /gh[pousr]_[A-Za-z0-9]{36,255}/g },
  { label: "GitHub fine-grained token", regex: /github_pat_[A-Za-z0-9_]{22,255}/g },
  { label: "SendGrid API key", regex: /SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}/g },
  { label: "Twilio API key SID", regex: /\bSK[0-9a-f]{32}\b/g },
  { label: "Mailgun API key", regex: /\bkey-[0-9a-zA-Z]{32}\b/g },
  { label: "Telegram bot token", regex: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g },
  { label: "Azure storage account key", regex: /AccountKey=[A-Za-z0-9+\/]{60,}={0,2}/g },
  { label: "JWT", regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
];

const SPECIFIC_PATTERNS = SECRET_PATTERNS.filter((p) => !p.generic);

/** Shannon entropy in bits per character. */
function shannonEntropy(str) {
  if (!str) return 0;
  const counts = new Map();
  for (const ch of str) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Cheap "does this look like a machine-generated secret rather than a
 * human-readable identifier" test for the generic patterns: mixes letters and
 * digits and has enough character variety. Returns the entropy when it passes,
 * or null when the value looks like a name/constant.
 */
function randomnessOf(matchText) {
  const quoted = /['"]([^'"]+)['"]\s*$/.exec(matchText);
  const value = quoted ? quoted[1] : matchText;
  const entropy = shannonEntropy(value);
  if (entropy >= 3.0 && /\d/.test(value) && /[A-Za-z]/.test(value)) return Math.round(entropy * 100) / 100;
  return null;
}

/**
 * Masks any known-secret substring inside a URL (a Slack webhook, a token in
 * a query string) so the URL list in report.md/--strings-out stays shareable.
 * The unmasked value is still recorded under potentialSecrets in report.json.
 */
function redactUrl(url) {
  let out = url;
  for (const { regex } of SPECIFIC_PATTERNS) {
    out = out.replace(regex, (m) => (PLACEHOLDER_REGEX.test(m) ? m : maskSecret(m)));
  }
  return out;
}

// Matches captured entirely against known placeholder/example wording get
// dropped — "YOUR_API_KEY_HERE" satisfies the generic 16+ char pattern but
// isn't a real credential, and flagging it just trains people to ignore the
// scan's output.
const PLACEHOLDER_REGEX = /YOUR[_-]?API|PLACEHOLDER|EXAMPLE|SAMPLE|CHANGE[_-]?ME|INSERT[_-]?KEY|DUMMY|XXXX|TEST[_-]?KEY|FAKE[_-]?KEY|AKIAIOSFODNN7EXAMPLE/i;

// Well-known third-party packages that dominate a decompiled tree but rarely
// hold anything about the app under review. Only used with --skip-libs, and
// only matched as top-level packages under a code root (jadx "sources/" or
// apktool "smali*/"), so an app's own com/acme/androidx isn't affected.
const THIRD_PARTY_PACKAGES = [
  "androidx",
  "android/support",
  "kotlin",
  "kotlinx",
  "com/google/android/gms",
  "com/google/android/material",
  "com/google/firebase",
  "com/google/gson",
  "com/google/protobuf",
  "com/squareup",
  "com/bumptech/glide",
  "okhttp3",
  "okio",
  "retrofit2",
  "io/reactivex",
  "org/jetbrains",
  "dagger",
  "javax",
];

/** "com.foo.Bar" | "com/foo/Bar" | "/com/foo/" -> "com/foo/Bar" */
function normalizePackage(pkg) {
  return String(pkg).trim().replace(/\./g, "/").replace(/^\/+|\/+$/g, "");
}

/**
 * Builds a predicate over a directory path relative to the scan root, true when
 * that directory is a package we were asked to skip.
 */
function buildExcluder({ skipLibs = false, excludePackages = [] } = {}) {
  const pkgs = new Set(excludePackages.map(normalizePackage).filter(Boolean));
  if (skipLibs) for (const p of THIRD_PARTY_PACKAGES) pkgs.add(p);
  if (!pkgs.size) return () => false;
  return (relDir) => {
    const parts = relDir.split(path.sep).join("/").split("/");
    if (parts.length < 2 || !/^(?:sources|smali.*)$/.test(parts[0])) return false;
    return pkgs.has(parts.slice(1).join("/"));
  };
}

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
 * Splits a raw --grep value into individual keyword terms on commas, except
 * that commas inside a /regex/flags literal are kept intact — so
 * "/a{1,3}/i,foo" is two terms, not three. A "/" only closes a regex literal
 * when it is unescaped, outside a [...] class, and followed by optional flags
 * and then a comma or the end of the input; anything that doesn't fit that
 * shape falls back to plain comma splitting.
 */
function splitKeywords(raw) {
  const parts = [];
  const n = raw.length;
  let i = 0;

  while (i < n) {
    while (i < n && /\s/.test(raw[i])) i++;
    if (i >= n) break;

    let end = -1;
    if (raw[i] === "/") {
      let inClass = false;
      for (let j = i + 1; j < n; j++) {
        const c = raw[j];
        if (c === "\\") {
          j++; // skip the escaped character
        } else if (c === "[") {
          inClass = true;
        } else if (c === "]") {
          inClass = false;
        } else if (c === "/" && !inClass) {
          const flags = /^[a-z]*/i.exec(raw.slice(j + 1))[0];
          const after = j + 1 + flags.length;
          if (/^\s*(,|$)/.test(raw.slice(after))) {
            end = after;
            break;
          }
        }
      }
    }

    if (end === -1) {
      const comma = raw.indexOf(",", i);
      end = comma === -1 ? n : comma;
    }

    const token = raw.slice(i, end).trim();
    if (token) parts.push(token);
    i = end + 1; // step over the separating comma
  }

  return parts;
}

/**
 * Splits a --grep CLI value ("firebase,MyCo,/api\\.foo\\.[a-z]+/i") into
 * compiled keyword matchers, separating out any that failed to compile so
 * the caller can warn about them without losing the valid ones.
 */
function parseKeywords(rawValue) {
  if (!rawValue) return { compiled: [], invalid: [] };
  const parts = splitKeywords(rawValue);
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
async function scanStrings(
  rootDir,
  { maxMatchesPerCategory = 200, maxUrls = 5000, keywords = [], skipLibs = false, excludePackages = [] } = {}
) {
  const isExcludedDir = buildExcluder({ skipLibs, excludePackages });
  let skippedDirs = 0;
  const urls = new Set();
  let urlsTruncated = false;
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
        if (isExcludedDir(path.relative(rootDir, full))) {
          skippedDirs++;
          continue;
        }
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
      for (const raw of urlMatches) {
        const u = redactUrl(raw);
        if (urls.has(u)) continue;
        if (urls.size < maxUrls) urls.add(u);
        else urlsTruncated = true;
      }

      const relFile = path.relative(rootDir, full);
      for (const { label, regex, generic } of SECRET_PATTERNS) {
        const matches = content.match(regex) || [];
        for (const m of matches) {
          if (PLACEHOLDER_REGEX.test(m)) continue;
          let entropy = null;
          if (generic) {
            entropy = randomnessOf(m);
            if (entropy === null) continue;
          }

          const key = `${label}::${m}`;
          let entryRec = secretsByKey.get(key);
          if (!entryRec) {
            if (secretsByKey.size >= maxMatchesPerCategory) continue;
            entryRec = { label, match: m, masked: maskSecret(m), entropy, files: new Set(), occurrences: 0 };
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
    ...(s.entropy !== null && s.entropy !== undefined ? { entropy: s.entropy } : {}),
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

  const urlList = Array.from(urls);
  return {
    urls: urlList,
    urlsTruncated,
    excluded: { libs: Boolean(skipLibs), packages: excludePackages.map(normalizePackage).filter(Boolean), skippedDirs },
    urlAnalysis: analyzeUrls(urlList),
    potentialSecrets,
    keywordMatches,
  };
}

module.exports = { scanStrings, parseKeywords, splitKeywords, shannonEntropy, redactUrl, buildExcluder, THIRD_PARTY_PACKAGES };
