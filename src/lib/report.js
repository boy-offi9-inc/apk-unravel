const fs = require("fs-extra");
const path = require("path");

function renderMarkdown(report) {
  const lines = [];
  lines.push(`# APK Analysis Report`);
  lines.push("");
  lines.push(`**File:** \`${report.apkFile}\``);
  if (report.input && report.input.kind === "bundle") {
    lines.push(
      `**Input:** ${report.input.container} bundle — analyzed \`${report.input.baseEntry}\`` +
        (report.input.partial ? ` (the other ${report.input.splitCount} split APK(s) were not analyzed)` : "")
    );
  }
  lines.push(`**Generated:** ${report.generatedAt}`);
  lines.push("");

  if (report.appIdentity) {
    lines.push(`**App:** ${report.appIdentity.label || "—"}`);
    if (report.appIdentity.iconOutputPath) {
      const iconRel = path.basename(report.appIdentity.iconOutputPath);
      lines.push(`**Icon:** \`${iconRel}\` (saved alongside this report)`);
      lines.push("");
      lines.push(`![app icon](./${iconRel})`);
    }
    lines.push("");
  }

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
    const TIER_LABEL = { runtime: "⚠️ dangerous (runtime prompt)", special: "⚠️ special access", normal: "normal" };
    for (const p of report.manifest.permissions) {
      const label = TIER_LABEL[p.tier] || (p.dangerous ? "⚠️ dangerous" : "normal");
      lines.push(`| \`${p.name}\` | ${label} |`);
    }
  } else {
    lines.push("_No permissions declared._");
  }
  lines.push("");

  lines.push(`## Security flags (${report.manifest.security.flags.length})`);
  lines.push("");
  if (report.manifest.security.flags.length) {
    lines.push(`| Flag | Severity | Detail |`);
    lines.push(`| --- | --- | --- |`);
    for (const f of report.manifest.security.flags) {
      lines.push(`| \`${f.flag}\` | ${f.severity} | ${f.detail} |`);
    }
  } else {
    lines.push("_No manifest-level security flags raised._");
  }
  lines.push("");
  lines.push(
    `_Cleartext traffic: ${report.manifest.security.usesCleartextTraffic ? "explicitly allowed" : "not explicitly allowed"} · Network security config: ${report.manifest.security.networkSecurityConfig ? `\`${report.manifest.security.networkSecurityConfig}\`` : "none referenced"}_`
  );
  lines.push("");

  lines.push(`## Deep links / custom URI schemes (${report.manifest.deepLinks.length})`);
  lines.push("");
  if (report.manifest.deepLinks.length) {
    lines.push(`| Component | URI pattern | Reachable externally |`);
    lines.push(`| --- | --- | --- |`);
    for (const l of report.manifest.deepLinks) {
      const uri = `${l.scheme || "*"}://${l.host || "*"}${l.path || ""}`;
      lines.push(`| \`${l.component}\` | \`${uri}\` | ${l.reachable ? "⚠️ yes" : "no"} |`);
    }
  } else {
    lines.push("_No deep links / custom URI schemes declared._");
  }
  lines.push("");

  const exported = report.manifest.flaggedExported;
  const unguarded = report.manifest.unguardedExported;
  lines.push(
    `## Exported / intent-filtered components (${exported.length}${unguarded ? `, ${unguarded.length} unguarded` : ""})`
  );
  lines.push("");
  if (exported.length) {
    lines.push(`| Kind | Name | Exposed via | Guard |`);
    lines.push(`| --- | --- | --- | --- |`);
    for (const c of exported) {
      let guard;
      if (c.launcher) guard = "launcher entry point (expected)";
      else if (c.guarded && c.weakGuard) guard = `⚠️ \`${c.permission}\` (custom permission with normal protection level — no real protection)`;
      else if (c.guarded) guard = `\`${c.permission}\``;
      else guard = "⚠️ none";
      lines.push(`| ${c.kind} | \`${c.name}\` | ${c.exposedVia || "—"} | ${guard} |`);
    }
    lines.push("");
    lines.push("_These are reachable from outside the app (explicitly exported, or exposed via an intent-filter). Ones without a permission guard are worth a manual look if they handle sensitive data._");
  } else {
    lines.push("_None found._");
  }
  lines.push("");

  if (report.stringScan) {
    lines.push(`## String scan`);
    lines.push("");
    const scan = report.stringScan;
    if (scan.excluded && (scan.excluded.libs || scan.excluded.packages.length)) {
      const what = [scan.excluded.libs ? "well-known third-party libraries (`--skip-libs`)" : null, scan.excluded.packages.length ? `\`${scan.excluded.packages.join("`, `")}\`` : null]
        .filter(Boolean)
        .join(" and ");
      lines.push(`_Excluded from this scan: ${what} — ${scan.excluded.skippedDirs} package folder(s) skipped._`);
      lines.push("");
    }
    const ua = scan.urlAnalysis;
    lines.push(`**URLs found:** ${scan.urls.length}${scan.urlsTruncated ? " (scan cap reached — more exist; see --strings-out)" : ""}`);
    if (ua && ua.domains.length) {
      lines.push("");
      lines.push(`**Top domains:** ${ua.domains.slice(0, 15).map((d) => `\`${d.host}\` (${d.count})`).join(", ")}`);
    }
    if (ua && ua.cleartextTotal) {
      lines.push("");
      lines.push(`**Cleartext \`http://\` URLs:** ${ua.cleartextTotal}`);
      for (const u of ua.cleartextUrls.slice(0, 15)) lines.push(`- \`${u}\``);
      if (ua.cleartextTotal > 15) lines.push(`- _...and ${ua.cleartextTotal - 15} more (see report.json)_`);
    }
    if (ua && ua.ipTotal) {
      lines.push("");
      lines.push(`**Raw-IP endpoints:** ${ua.ipTotal}`);
      for (const u of ua.ipUrls.slice(0, 15)) lines.push(`- \`${u}\``);
    }
    if (ua && ua.notable.length) {
      lines.push("");
      lines.push(`**Cloud endpoints worth checking for open access:**`);
      for (const n of ua.notable) lines.push(`- ${n.kind}: \`${n.url}\``);
    }
    if (scan.urls.length) {
      lines.push("");
      lines.push(`<details><summary>All URLs (first 50)</summary>`);
      lines.push("");
      for (const u of scan.urls.slice(0, 50)) {
        lines.push(`- \`${u}\``);
      }
      if (scan.urls.length > 50) {
        lines.push(`- _...and ${scan.urls.length - 50} more (see report.json)_`);
      }
      lines.push("");
      lines.push(`</details>`);
    }
    lines.push("");
    lines.push(`**Potential secrets flagged:** ${report.stringScan.potentialSecrets.length} unique`);
    if (report.stringScan.potentialSecrets.length) {
      lines.push("");
      lines.push(`| Type | Seen in | Occurrences | Value (masked) |`);
      lines.push(`| --- | --- | --- | --- |`);
      for (const s of report.stringScan.potentialSecrets.slice(0, 50)) {
        const fileList = s.files.map((f) => `\`${f}\``).join(", ") + (s.truncatedFileList ? ", …" : "");
        lines.push(`| ${s.label} | ${fileList} | ${s.occurrences} | \`${s.masked}\` |`);
      }
      lines.push("");
      lines.push(
        "_Heuristic matches only — verify each before treating it as a real credential. Values are masked here; full values are in report.json._"
      );
    }
    lines.push("");

    if (report.stringScan.keywordMatches && report.stringScan.keywordMatches.length) {
      lines.push(`**Custom keyword matches (--grep):** ${report.stringScan.keywordMatches.length} unique`);
      lines.push("");
      lines.push(`| Keyword | Seen in | Occurrences | Match |`);
      lines.push(`| --- | --- | --- | --- |`);
      for (const k of report.stringScan.keywordMatches.slice(0, 50)) {
        const fileList = k.files.map((f) => `\`${f}\``).join(", ") + (k.truncatedFileList ? ", …" : "");
        const truncatedMatch = k.match.length > 80 ? k.match.slice(0, 80) + "…" : k.match;
        lines.push(`| \`${k.keyword}\` | ${fileList} | ${k.occurrences} | \`${truncatedMatch}\` |`);
      }
      lines.push("");
    }
  }

  if (report.nativeLibs?.present) {
    lines.push(`## Native libraries`);
    lines.push("");
    lines.push(`| ABI | .so files | 64-bit | Legacy | 16 KB aligned |`);
    lines.push(`| --- | --- | --- | --- | --- |`);
    for (const a of report.nativeLibs.abis) {
      let aligned = "n/a";
      if (a.is64Bit && a.libraryCount) {
        const bad = (a.unaligned16k || []).length;
        aligned = bad ? `⚠️ ${a.libraryCount - bad}/${a.libraryCount}` : (a.unreadable || []).length === a.libraryCount ? "?" : "✓ all";
      }
      lines.push(`| \`${a.abi}\` | ${a.libraryCount} | ${a.is64Bit ? "✓" : "—"} | ${a.legacy ? "⚠️ yes" : "—"} | ${aligned} |`);
    }
    if (report.nativeLibs.flags.length) {
      lines.push("");
      for (const f of report.nativeLibs.flags) {
        lines.push(`- **[${f.severity}]** \`${f.flag}\` — ${f.detail}`);
      }
    }
    lines.push("");
  }

  lines.push(`## Output locations`);
  lines.push("");
  if (report.manifestSource === "jadx") {
    lines.push("- manifest/resources read from jadx's decoded output (`--jadx-only`)");
  }
  if (report.outputPaths.apktool) lines.push(`- apktool output: \`${report.outputPaths.apktool}\``);
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

/**
 * Copy of the report that is safe to print to stdout / pipe elsewhere: the
 * full (unmasked) value of each potential secret is dropped, matching what
 * report.md and --strings-out already do. Only report.json on disk keeps them.
 */
function toPublicReport(report) {
  if (!report.stringScan) return report;
  return {
    ...report,
    stringScan: {
      ...report.stringScan,
      potentialSecrets: report.stringScan.potentialSecrets.map(({ match, ...rest }) => rest),
    },
  };
}

module.exports = { writeReport, renderMarkdown, toPublicReport };
