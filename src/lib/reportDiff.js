const fs = require("fs-extra");
const path = require("path");

/**
 * Compares the current run's report against a previous report.json so an app
 * can be tracked across versions: what permissions, exported components, deep
 * links, security flags and unique secrets appeared or disappeared.
 */

const setOf = (xs) => new Set(xs || []);
const sortStr = (xs) => [...xs].sort();

function addedRemoved(oldSet, newSet) {
  const added = sortStr([...newSet].filter((x) => !oldSet.has(x)));
  const removed = sortStr([...oldSet].filter((x) => !newSet.has(x)));
  return { added, removed };
}

function exportedKey(c) {
  return `${c.kind}:${c.name}`;
}

function deepLinkKey(l) {
  return `${l.component}|${l.scheme || "*"}://${l.host || "*"}${l.path || ""}`;
}

function secretKey(s) {
  return s.match !== undefined ? `${s.label}::${s.match}` : `${s.label}::${s.masked}`;
}

function diffReports(oldReport, newReport) {
  const oldM = (oldReport && oldReport.manifest) || {};
  const newM = newReport.manifest || {};
  const oldS = oldReport && oldReport.stringScan;
  const newS = newReport.stringScan;

  const permissions = addedRemoved(setOf((oldM.permissions || []).map((p) => p.name)), setOf((newM.permissions || []).map((p) => p.name)));
  const exported = addedRemoved(setOf((oldM.flaggedExported || []).map(exportedKey)), setOf((newM.flaggedExported || []).map(exportedKey)));
  const deepLinks = addedRemoved(setOf((oldM.deepLinks || []).map(deepLinkKey)), setOf((newM.deepLinks || []).map(deepLinkKey)));
  const securityFlags = addedRemoved(setOf(((oldM.security && oldM.security.flags) || []).map((f) => f.flag)), setOf(((newM.security && newM.security.flags) || []).map((f) => f.flag)));
  const secrets = addedRemoved(setOf(((oldS && oldS.potentialSecrets) || []).map(secretKey)), setOf(((newS && newS.potentialSecrets) || []).map(secretKey)));

  return {
    comparedAgainst: (oldReport && oldReport.generatedAt) || null,
    permissions,
    exported,
    deepLinks,
    securityFlags,
    secrets,
  };
}

function countLine(diff) {
  const parts = [];
  if (diff.permissions.added.length || diff.permissions.removed.length) {
    parts.push(`+${diff.permissions.added.length}/-${diff.permissions.removed.length} permissions`);
  }
  if (diff.exported.added.length || diff.exported.removed.length) {
    parts.push(`+${diff.exported.added.length}/-${diff.exported.removed.length} exported components`);
  }
  if (diff.deepLinks.added.length || diff.deepLinks.removed.length) {
    parts.push(`+${diff.deepLinks.added.length}/-${diff.deepLinks.removed.length} deep links`);
  }
  if (diff.securityFlags.added.length || diff.securityFlags.removed.length) {
    parts.push(`+${diff.securityFlags.added.length}/-${diff.securityFlags.removed.length} security flags`);
  }
  if (diff.secrets.added.length) parts.push(`${diff.secrets.added.length} new secret(s)`);
  if (diff.secrets.removed.length) parts.push(`${diff.secrets.removed.length} secret(s) gone`);
  return parts.length ? parts.join(", ") : "no differences";
}

function section(lines, title, { added, removed }, label = (x) => `\`${x}\``) {
  lines.push(`### ${title}`);
  lines.push("");
  if (!added.length && !removed.length) {
    lines.push("_No changes._");
    lines.push("");
    return;
  }
  for (const x of added) lines.push(`- **+** ${label(x)}`);
  for (const x of removed) lines.push(`- **−** ${label(x)}`);
  lines.push("");
}

function renderDiffMarkdown(diff, currentReport) {
  const lines = [];
  lines.push(`# Report diff`);
  lines.push("");
  lines.push(`**Current:** \`${currentReport.apkFile}\` — ${currentReport.manifest.versionName || "—"} (${currentReport.manifest.versionCode || "—"})`);
  if (diff.comparedAgainst) lines.push(`**Compared against a report generated:** ${diff.comparedAgainst}`);
  lines.push("");
  lines.push(`**Summary:** ${countLine(diff)}`);
  lines.push("");
  section(lines, "Permissions", diff.permissions);
  section(lines, "Exported components", diff.exported, (k) => `\`${k.replace(":", " · ")}\``);
  section(lines, "Deep links", diff.deepLinks, (k) => {
    const [comp, uri] = k.split("|");
    return `\`${uri}\` → ${comp}`;
  });
  section(lines, "Security flags", diff.securityFlags);
  section(lines, "Potential secrets (unique)", diff.secrets, (k) => {
    const [label, value] = k.split("::");
    return `${label} — \`${value}\``;
  });
  return lines.join("\n");
}

async function writeDiff(diff, currentReport, outDir) {
  const mdPath = path.join(outDir, "diff.md");
  await fs.writeFile(mdPath, renderDiffMarkdown(diff, currentReport), "utf8");
  return { mdPath };
}

module.exports = { diffReports, renderDiffMarkdown, writeDiff, countLine };
