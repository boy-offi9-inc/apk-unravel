const fs = require("fs-extra");
const path = require("path");

/**
 * Heuristic check of whether a declared deep link is actually handled by code.
 * For each link we look for the target component's class file in jadx's
 * decompiled sources and grep just that file for the usual intent-entry points:
 * getIntent() / getData() / onNewIntent(). Cheap file-existence + regex work —
 * a hint for the reviewer, not proof of correct handling.
 */
const HANDLER_HINTS = [
  { key: "readsIntent", regex: /\bgetIntent\s*\(/ },
  { key: "readsData", regex: /\bgetData\s*\(/ },
  { key: "onNewIntent", regex: /\bonNewIntent\s*\(/ },
];

/** "com.acme.Deep$Inner" -> ["com/acme/Deep", "com/acme/Deep$Inner"] */
function candidateClassPaths(component) {
  const base = String(component || "").replace(/\./g, "/");
  if (!base) return [];
  const idx = base.indexOf("$");
  return idx === -1 ? [base] : [base, base.slice(0, idx)];
}

function verdictFor(hints, classFound) {
  if (!classFound) return "class-not-found";
  if (!hints.readsIntent && !hints.onNewIntent) return "no-intent-read";
  if (hints.readsData || hints.onNewIntent) return "reads-uri";
  return "reads-intent";
}

/**
 * @param {Array} deepLinks - manifest.deepLinks entries ({ scheme, host, path, mimeType, component })
 * @param {string} jadxSourcesDir - <jadx out>/sources
 */
async function analyzeDeepLinks(deepLinks, jadxSourcesDir) {
  const results = [];
  for (const link of deepLinks || []) {
    const uri = `${link.scheme || "*"}://${link.host || "*"}${link.path || ""}`;
    const rel = candidateClassPaths(link.component);
    let classFile = null;
    let content = null;
    for (const candidate of rel) {
      for (const ext of [".java", ".kt"]) {
        const full = path.join(jadxSourcesDir, candidate + ext);
        if (await fs.pathExists(full)) {
          classFile = path.join(candidate + ext);
          try {
            content = await fs.readFile(full, "utf8");
          } catch {
            content = null;
          }
          break;
        }
      }
      if (classFile) break;
    }
    const hints = {};
    for (const h of HANDLER_HINTS) hints[h.key] = classFile && content ? h.regex.test(content) : false;
    const classFound = Boolean(classFile && content);
    results.push({
      component: link.component,
      uri,
      classFound,
      classFile: classFound ? classFile : null,
      ...hints,
      verdict: verdictFor(hints, classFound),
    });
  }
  return { analyzed: results.length, links: results };
}

module.exports = { analyzeDeepLinks, candidateClassPaths, verdictFor };
