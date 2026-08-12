const fs = require("fs-extra");
const path = require("path");

function renderMarkdown(report) {
  const lines = [];
  lines.push(`# APK Analysis Report`);
  lines.push("");
  lines.push(`**File:** \`${report.apkFile}\``);
  lines.push(`**Generated:** ${report.generatedAt}`);
  lines.push("");

  lines.push(`## Package`);
  lines.push("");
  lines.push(`| Field | Value |`);
  lines.push(`| --- | --- |`);
  lines.push(`| Package name | \`${report.manifest.packageName || "—"}\` |`);
  lines.push(`| Version | ${report.manifest.versionName || "—"} (code ${report.manifest.versionCode || "—"}) |`);
  lines.push(`| Min SDK | ${report.manifest.minSdk || "—"} |`);
  lines.push(`| Target SDK | ${report.manifest.targetSdk || "—"} |`);
  lines.push("");

  lines.push(`## Permissions (${report.manifest.permissions.length} total, ${report.manifest.dangerousPermissions.length} flagged)`);
  lines.push("");
  if (report.manifest.permissions.length) {
    lines.push(`| Permission | Risk |`);
    lines.push(`| --- | --- |`);
    for (const p of report.manifest.permissions) {
      lines.push(`| \`${p.name}\` | ${p.dangerous ? "⚠️ dangerous" : "normal"} |`);
    }
  } else {
    lines.push("_No permissions declared._");
  }
  lines.push("");

  lines.push(`## Exported / intent-filtered components (${report.manifest.flaggedExported.length})`);
  lines.push("");
  if (report.manifest.flaggedExported.length) {
    lines.push(`| Kind | Name |`);
    lines.push(`| --- | --- |`);
    for (const c of report.manifest.flaggedExported) {
      lines.push(`| ${c.kind} | \`${c.name}\` |`);
    }
    lines.push("");
    lines.push("_These are reachable from outside the app (explicitly exported, or exposed via an intent-filter). Worth a manual look if any handle sensitive data._");
  } else {
    lines.push("_None found._");
  }
  lines.push("");

  if (report.stringScan) {
    lines.push(`## String scan`);
    lines.push("");
    lines.push(`**URLs found:** ${report.stringScan.urls.length}`);
    if (report.stringScan.urls.length) {
      lines.push("");
      for (const u of report.stringScan.urls.slice(0, 50)) {
        lines.push(`- \`${u}\``);
      }
      if (report.stringScan.urls.length > 50) {
        lines.push(`- _...and ${report.stringScan.urls.length - 50} more (see report.json)_`);
      }
    }
    lines.push("");
    lines.push(`**Potential secrets flagged:** ${report.stringScan.potentialSecrets.length}`);
    if (report.stringScan.potentialSecrets.length) {
      lines.push("");
      lines.push(`| Type | File | Match (truncated) |`);
      lines.push(`| --- | --- | --- |`);
      for (const s of report.stringScan.potentialSecrets.slice(0, 50)) {
        const truncated = s.match.length > 60 ? s.match.slice(0, 60) + "…" : s.match;
        lines.push(`| ${s.label} | \`${s.file}\` | \`${truncated}\` |`);
      }
      lines.push("");
      lines.push("_Heuristic matches only — verify each before treating it as a real credential._");
    }
    lines.push("");
  }

  lines.push(`## Output locations`);
  lines.push("");
  lines.push(`- apktool output: \`${report.outputPaths.apktool}\``);
  if (report.outputPaths.jadx) lines.push(`- jadx output: \`${report.outputPaths.jadx}\``);
  lines.push("");

  return lines.join("\n");
}

async function writeReport(report, outDir) {
  const jsonPath = path.join(outDir, "report.json");
  const mdPath = path.join(outDir, "report.md");
  await fs.writeJson(jsonPath, report, { spaces: 2 });
  await fs.writeFile(mdPath, renderMarkdown(report), "utf8");
  return { jsonPath, mdPath };
}

module.exports = { writeReport, renderMarkdown };
