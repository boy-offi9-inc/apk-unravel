const fs = require("fs-extra");
const path = require("path");
const { compileKeyword } = require("./stringScan");

/**
 * User-defined detection rules, so the scan isn't limited to the patterns
 * baked into apk-unravel. A rule is either
 *   - a SECRET rule: matches are reported under "potential secrets" with the
 *     value masked in report.md / --json / --strings-out (full value only in
 *     report.json on disk), exactly like the built-in detectors; or
 *   - a MATCH rule: matches are reported verbatim under keyword matches.
 *
 * Sources (all combinable):
 *   --rule "name=/regex/flags"      repeatable, secret rule
 *   --rule "name=literal text"      literal, case-insensitive
 *   --rules-file rules.json|.txt    many rules (JSON also supports kind/minEntropy)
 *   --grep-file words.txt           one keyword or /regex/ per line -> match rules
 */

class RuleError extends Error {}

// "name=" prefix: short, no slash/regex punctuation — so "/api_key=.../" is
// never mistaken for a rule called "/api_key".
const NAME_PREFIX = /^([A-Za-z0-9][\w .:@-]{0,59})=(.+)$/s;

function compileOne({ name, pattern, kind = "secret", minEntropy, origin }) {
  const compiled = compileKeyword(pattern);
  if (compiled.error) throw new RuleError(`${origin}: invalid pattern ${pattern} — ${compiled.error}`);
  // A pattern that matches "" would "find" a hit at every position of every file.
  if (new RegExp(compiled.regex.source, compiled.regex.flags.replace("g", "")).test("")) {
    throw new RuleError(`${origin}: pattern ${pattern} matches the empty string — make it more specific`);
  }
  if (minEntropy !== undefined && (typeof minEntropy !== "number" || !(minEntropy > 0 && minEntropy <= 8))) {
    throw new RuleError(`${origin}: minEntropy must be a number between 0 and 8 (bits per character)`);
  }
  if (kind !== "secret" && kind !== "match") throw new RuleError(`${origin}: kind must be "secret" or "match", got "${kind}"`);
  return { name, kind, regex: compiled.regex, minEntropy, source: pattern };
}

/** Parses one "--rule" value or one line of a .txt rules file. */
function parseRuleSpec(spec, { origin, index }) {
  const m = NAME_PREFIX.exec(spec);
  const name = m ? m[1].trim() : `rule ${index}`;
  const pattern = m ? m[2] : spec;
  if (!pattern.trim()) throw new RuleError(`${origin}: empty pattern`);
  return compileOne({ name, pattern, origin });
}

function parseTxtRules(text, file) {
  const rules = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    rules.push(parseRuleSpec(line, { origin: `${path.basename(file)}:${i + 1}`, index: rules.length + 1 }));
  });
  return rules;
}

function parseJsonRules(text, file) {
  const base = path.basename(file);
  let data;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new RuleError(`${base}: not valid JSON (${err.message})`);
  }
  const list = Array.isArray(data) ? data : data && Array.isArray(data.rules) ? data.rules : null;
  if (!list) throw new RuleError(`${base}: expected an array of rules, or an object with a "rules" array`);

  return list.map((r, i) => {
    const origin = `${base} rule #${i + 1}`;
    if (!r || typeof r !== "object") throw new RuleError(`${origin}: must be an object`);
    if (!r.name || typeof r.name !== "string") throw new RuleError(`${origin}: "name" is required`);
    const hasRegex = typeof r.regex === "string" && r.regex.length > 0;
    const hasKeyword = typeof r.keyword === "string" && r.keyword.length > 0;
    if (hasRegex === hasKeyword) throw new RuleError(`${origin} ("${r.name}"): give exactly one of "regex" or "keyword"`);
    if (r.flags !== undefined && (typeof r.flags !== "string" || !/^[gimsu]*$/.test(r.flags))) {
      throw new RuleError(`${origin} ("${r.name}"): flags may only contain g, i, m, s, u`);
    }
    const pattern = hasRegex ? `/${r.regex.replace(/\//g, "\\/")}/${r.flags || ""}` : r.keyword;
    return compileOne({ name: r.name, pattern, kind: r.kind, minEntropy: r.minEntropy, origin: `${origin} ("${r.name}")` });
  });
}

async function readText(file, what) {
  try {
    return await fs.readFile(file, "utf8");
  } catch (err) {
    throw new RuleError(`Can't read ${what} ${file}: ${err.code || err.message}`);
  }
}

/**
 * Loads every user-defined rule from the CLI options. Throws RuleError on the
 * first problem — callers run this BEFORE the slow decompile so a typo in a
 * rule fails in milliseconds, not after minutes of jadx.
 *
 * @param {{ rule?: string[], rulesFile?: string[], grepFile?: string[] }} options
 * @returns {Promise<{ secretRules: object[], matchRules: object[] }>}
 */
async function loadCustomRules(options = {}) {
  const rules = [];

  (options.rule || []).forEach((spec, i) => {
    rules.push(parseRuleSpec(spec, { origin: `--rule #${i + 1}`, index: rules.length + 1 }));
  });

  for (const file of options.rulesFile || []) {
    const text = await readText(file, "rules file");
    rules.push(...(/\.json$/i.test(file) ? parseJsonRules(text, file) : parseTxtRules(text, file)));
  }

  for (const file of options.grepFile || []) {
    const text = await readText(file, "keyword file");
    text.split(/\r?\n/).forEach((raw, i) => {
      const line = raw.trim();
      if (!line || line.startsWith("#")) return;
      rules.push(compileOne({ name: line, pattern: line, kind: "match", origin: `${path.basename(file)}:${i + 1}` }));
    });
  }

  return {
    secretRules: rules.filter((r) => r.kind === "secret"),
    matchRules: rules.filter((r) => r.kind === "match"),
  };
}

/** Collector for repeatable commander options. */
const collect = (value, previous = []) => [...previous, value];

module.exports = { loadCustomRules, parseRuleSpec, RuleError, collect };
