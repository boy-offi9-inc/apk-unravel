const fs = require("fs-extra");
const path = require("path");

function csvEscape(value) {
  const s = String(value ?? "");
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function toCsv(stringScan) {
  const rows = [["type", "label", "value", "occurrences", "files"]];

  for (const u of stringScan.urls) {
    rows.push(["url", "", u, "1", ""]);
  }
  for (const s of stringScan.potentialSecrets) {
    rows.push(["secret", s.label, s.masked, String(s.occurrences), s.files.join(";")]);
  }
  for (const k of stringScan.keywordMatches || []) {
    rows.push(["keyword", k.keyword, k.match, String(k.occurrences), k.files.join(";")]);
  }

  return rows.map((row) => row.map(csvEscape).join(",")).join("\n") + "\n";
}

/**
 * Writes string/keyword scan findings to a standalone file, separate from
 * the full report.json/report.md — useful for piping into another tool
 * (spreadsheet review, a SIEM import, a diff against a previous scan) without
 * needing to extract the relevant section out of the full report by hand.
 * Format is inferred from the file extension: .csv or .json (default).
 *
 * Secret values are written in their masked form here too, matching
 * report.md — this file is just as likely to get shared/attached as the
 * main report is, so it shouldn't be a route around that protection.
 * Keyword matches are NOT secrets by definition (they're whatever the user
 * searched for) so those are written in full.
 */
async function writeStringsExport(stringScan, outPath) {
  await fs.ensureDir(path.dirname(outPath));
  const ext = path.extname(outPath).toLowerCase();

  if (ext === ".csv") {
    await fs.writeFile(outPath, toCsv(stringScan), "utf8");
  } else {
    const safeSecrets = stringScan.potentialSecrets.map(({ match, ...rest }) => rest); // omit unmasked match
    await fs.writeFile(
      outPath,
      JSON.stringify({ urls: stringScan.urls, potentialSecrets: safeSecrets, keywordMatches: stringScan.keywordMatches || [], urlAnalysis: stringScan.urlAnalysis || null, urlsTruncated: Boolean(stringScan.urlsTruncated) }, null, 2),
      "utf8"
    );
  }

  return outPath;
}

module.exports = { writeStringsExport };
