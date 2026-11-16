// End-to-end + unit tests for deep-link analysis, report diffing, parallel
// tool runs and the distinct exit codes.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { tmpdir, rmrf, write, fakeBin, makeApk, MANIFEST } = require("./_helpers");

const BIN = path.join(__dirname, "..", "bin", "apk-unravel.js");
const posix = { skip: process.platform === "win32" && "needs a POSIX shell for the fake binaries" };

function setup(t, { deepActivitySrc = null, slowTool = false } = {}) {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const manifestSrc = write(path.join(dir, "m.xml"), MANIFEST);
  const apktool = fakeBin(
    path.join(dir, "apktool"),
    `OUT=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && OUT="$2"; shift; done
mkdir -p "$OUT"; cp "${manifestSrc}" "$OUT/AndroidManifest.xml"`
  );
  let jadxBody = `OUT="$2"; mkdir -p "$OUT/sources/com/acme" "$OUT/resources"; cp "${manifestSrc}" "$OUT/resources/AndroidManifest.xml"`;
  if (deepActivitySrc) {
    const srcFile = write(path.join(dir, "DeepActivity.java"), deepActivitySrc);
    jadxBody += `; mkdir -p "$OUT/sources/com/acme/demo"; cp "${srcFile}" "$OUT/sources/com/acme/demo/DeepActivity.java"`;
  }
  if (slowTool) jadxBody = `sleep 0.5; ${jadxBody}`;
  const jadx = fakeBin(path.join(dir, "jadx"), jadxBody);
  const apk = write(path.join(dir, "app.apk"), makeApk());
  const env = { ...process.env, CI: "1", APKTOOL_PATH: apktool, JADX_PATH: jadx };
  const run = (...args) => spawnSync(process.execPath, [BIN, "decompile", apk, "-o", path.join(dir, "out"), ...args], { env, encoding: "utf8" });
  return { dir, run, apk };
}

// ---- deep-link analysis -----------------------------------------------------

const HANDLES_URI = `package com.acme;
import android.app.Activity; import android.content.Intent; import android.net.Uri;
public class DeepActivity extends Activity {
  @Override protected void onNewIntent(Intent i) { Uri u = i.getData(); }
}`;
const IGNORES_URI = `package com.acme;
import android.app.Activity; import android.content.Intent;
public class DeepActivity extends Activity {
  @Override protected void onCreate(android.os.Bundle b) { Intent i = getIntent(); }
}`;

test("--deep-link-analysis: handled link reads the URI, unhandled one is flagged", posix, (t) => {
  const { dir, run } = setup(t, { deepActivitySrc: HANDLES_URI });
  const r = run("--deep-link-analysis", "--json");
  assert.equal(r.status, 0, r.stderr);
  const links = JSON.parse(r.stdout).deepLinkAnalysis.links;
  const deep = links.find((l) => l.component === "com.acme.demo.DeepActivity");
  const priv = links.find((l) => l.component === "com.acme.demo.PrivateActivity");
  assert.equal(deep.classFound, true);
  assert.equal(deep.readsData || deep.onNewIntent, true);
  assert.equal(deep.verdict, "reads-uri");
  assert.match(deep.classFile, /com\/acme\/demo\/DeepActivity\.java/);
  assert.equal(priv.classFound, false);
  assert.equal(priv.verdict, "class-not-found");
  const md = fs.readFileSync(path.join(dir, "out", "report.md"), "utf8");
  assert.match(md, /Deep-link handling/);
  assert.match(md, /reads the URI/);
  assert.match(md, /class not found/);
});

test("--deep-link-analysis: class found but URI never read -> reads-intent verdict", posix, (t) => {
  const { run } = setup(t, { deepActivitySrc: IGNORES_URI });
  const r = run("--deep-link-analysis", "--json");
  const links = JSON.parse(r.stdout).deepLinkAnalysis.links;
  const deep = links.find((l) => l.component === "com.acme.demo.DeepActivity");
  assert.equal(deep.verdict, "reads-intent");
});

test("deep-link analysis is off by default", posix, (t) => {
  const { run } = setup(t, { deepActivitySrc: HANDLES_URI });
  const r = run("--json");
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).deepLinkAnalysis, undefined);
});

test("deepLinks lib: inner classes fall back to the outer class file", async (t) => {
  const { candidateClassPaths, verdictFor } = require("../src/lib/deepLinks");
  assert.deepEqual(candidateClassPaths("com.acme.Deep$Inner"), ["com/acme/Deep$Inner", "com/acme/Deep"]);
  assert.deepEqual(candidateClassPaths(""), []);
  assert.equal(verdictFor({}, true), "no-intent-read");
  assert.equal(verdictFor({ readsIntent: true, readsData: true }, true), "reads-uri");
});

// ---- diff -------------------------------------------------------------------

function oldReportFixture() {
  return {
    generatedAt: "2026-01-01T00:00:00.000Z",
    apkFile: "/tmp/old.apk",
    manifest: {
      versionName: "1.0.0",
      versionCode: "1",
      permissions: [{ name: "android.permission.INTERNET" }, { name: "android.permission.CAMERA" }],
      flaggedExported: [{ kind: "activities", name: "com.acme.Main" }, { kind: "services", name: "com.acme.Svc" }],
      deepLinks: [{ component: "com.acme.Main", scheme: "acme", host: "open", path: null }],
      security: { flags: [{ flag: "debuggable" }] },
    },
    stringScan: {
      potentialSecrets: [{ label: "Google API key", match: "AIza" + "A".repeat(35) }],
    },
  };
}

test("diffReports: detects new/removed permissions, exports, links, flags and secrets", (t) => {
  const { diffReports, countLine } = require("../src/lib/reportDiff");
  const newReport = {
    generatedAt: "2026-06-01T00:00:00.000Z",
    manifest: {
      permissions: [{ name: "android.permission.INTERNET" }, { name: "android.permission.RECORD_AUDIO" }],
      flaggedExported: [{ kind: "activities", name: "com.acme.Main" }, { kind: "receivers", name: "com.acme.R" }],
      deepLinks: [
        { component: "com.acme.Main", scheme: "acme", host: "open", path: null },
        { component: "com.acme.Other", scheme: "web", host: null, path: null },
      ],
      security: { flags: [{ flag: "debuggable" }, { flag: "allowBackup" }] },
    },
    stringScan: {
      potentialSecrets: [
        { label: "Google API key", match: "AIza" + "A".repeat(35) },
        { label: "Slack token", match: "xoxb-123" },
      ],
    },
  };
  const d = diffReports(oldReportFixture(), newReport);
  assert.deepEqual(d.permissions.added, ["android.permission.RECORD_AUDIO"]);
  assert.deepEqual(d.permissions.removed, ["android.permission.CAMERA"]);
  assert.deepEqual(d.exported.added, ["receivers:com.acme.R"]);
  assert.deepEqual(d.exported.removed, ["services:com.acme.Svc"]);
  assert.deepEqual(d.deepLinks.added, ["com.acme.Other|web://*"]);
  assert.deepEqual(d.securityFlags.added, ["allowBackup"]);
  assert.deepEqual(d.secrets.added, ["Slack token::xoxb-123"]);
  assert.deepEqual(d.secrets.removed, []);
  assert.match(countLine(d), /\+1\/-1 permissions/);
});

test("diffReports: works with missing stringScan / empty manifest sections", (t) => {
  const { diffReports } = require("../src/lib/reportDiff");
  const d = diffReports(oldReportFixture(), { manifest: { permissions: [], flaggedExported: [], deepLinks: [], security: { flags: [] } } });
  assert.equal(d.secrets.removed.length, 1);
  assert.equal(d.exported.removed.length, 2);
});

test("diff rendering: markdown has +/- sections", (t) => {
  const { diffReports, renderDiffMarkdown } = require("../src/lib/reportDiff");
  const d = diffReports(oldReportFixture(), { manifest: { permissions: [], flaggedExported: [], deepLinks: [], security: { flags: [] } } });
  const md = renderDiffMarkdown(d, { apkFile: "x.apk", manifest: {} });
  assert.match(md, /# Report diff/);
  assert.match(md, /^- \*\*−\*\* `android\.permission\.CAMERA`$/m);
});

test("--diff against a previous report.json writes diff.md and prints a summary", posix, (t) => {
  const { dir, run } = setup(t);
  const oldJson = path.join(dir, "old-report.json");
  fs.writeFileSync(oldJson, JSON.stringify(oldReportFixture()));
  const r = run("--json", "--diff", oldJson);
  assert.equal(r.status, 0, r.stderr);
  const diffMd = fs.readFileSync(path.join(dir, "out", "diff.md"), "utf8");
  assert.match(diffMd, /# Report diff/);
  assert.match(diffMd, /Google API key/); // the old report's secret is gone in this run
  assert.match(diffMd, /Potential secrets/);
  assert.ok(fs.existsSync(path.join(dir, "out", "diff.md")));
});

test("--diff with a missing/unreadable previous report warns but the run still succeeds", posix, (t) => {
  const { run } = setup(t);
  const r = run("--json", "--diff", "/no/such/report.json");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /Could not diff/);
});

// ---- exit codes -------------------------------------------------------------

test("tool failure exits 3 when apktool cannot run", posix, (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const apk = write(path.join(dir, "app.apk"), makeApk());
  const bad = fakeBin(path.join(dir, "apktool"), "exit 7");
  const r = spawnSync(process.execPath, [BIN, "decompile", apk, "-o", path.join(dir, "out")], {
    env: { ...process.env, CI: "1", APKTOOL_PATH: bad, JADX_PATH: path.join(dir, "jadx") },
    encoding: "utf8",
  });
  assert.equal(r.status, 3, r.stderr);
  assert.match(r.stderr, /apktool/);
});

test("tool failure exits 3 when jadx produces no output", posix, (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const manifestSrc = write(path.join(dir, "m.xml"), MANIFEST);
  const apktool = fakeBin(path.join(dir, "apktool"), `OUT=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && OUT="$2"; shift; done; mkdir -p "$OUT"; cp "${manifestSrc}" "$OUT/AndroidManifest.xml"`);
  const badJadx = fakeBin(path.join(dir, "jadx"), "exit 5");
  const apk = write(path.join(dir, "app.apk"), makeApk());
  const r = spawnSync(process.execPath, [BIN, "decompile", apk, "-o", path.join(dir, "out")], {
    env: { ...process.env, CI: "1", APKTOOL_PATH: apktool, JADX_PATH: badJadx },
    encoding: "utf8",
  });
  assert.equal(r.status, 3, r.stderr);
});

test("jadx partial success (non-zero exit with output) exits 4 and still writes the report", posix, (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const manifestSrc = write(path.join(dir, "m.xml"), MANIFEST);
  const apktool = fakeBin(path.join(dir, "apktool"), `OUT=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && OUT="$2"; shift; done; mkdir -p "$OUT"; cp "${manifestSrc}" "$OUT/AndroidManifest.xml"`);
  const jadx = fakeBin(
    path.join(dir, "jadx"),
    `OUT="$2"; mkdir -p "$OUT/sources" "$OUT/resources"; cp "${manifestSrc}" "$OUT/resources/AndroidManifest.xml"; echo 'class X{}' > "$OUT/sources/X.java"; exit 1`
  );
  const apk = write(path.join(dir, "app.apk"), makeApk());
  const r = spawnSync(process.execPath, [BIN, "decompile", apk, "-o", path.join(dir, "out")], {
    env: { ...process.env, CI: "1", APKTOOL_PATH: apktool, JADX_PATH: jadx },
    encoding: "utf8",
  });
  assert.equal(r.status, 4, r.stderr);
  assert.ok(fs.existsSync(path.join(dir, "out", "report.json")));
});

// ---- parallel tool runs -----------------------------------------------------

test("apktool and jadx run concurrently (both slower than the run's wall time implies)", posix, (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const manifestSrc = write(path.join(dir, "m.xml"), MANIFEST);
  const started = path.join(dir, "started.txt");
  const mkSlow = (name, marker) =>
    fakeBin(path.join(dir, name), `echo "${marker}" >> "${started}"; sleep 0.6; OUT=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && OUT="$2"; shift; done; mkdir -p "$OUT"; cp "${manifestSrc}" "$OUT/AndroidManifest.xml"`);
  const apktool = mkSlow("apktool", "apktool-started");
  const jadx = fakeBin(
    path.join(dir, "jadx"),
    `echo "jadx-started" >> "${started}"; sleep 0.6; OUT="$2"; mkdir -p "$OUT/sources" "$OUT/resources"; cp "${manifestSrc}" "$OUT/resources/AndroidManifest.xml"`
  );
  const apk = write(path.join(dir, "app.apk"), makeApk());
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [BIN, "decompile", apk, "-o", path.join(dir, "out")], {
    env: { ...process.env, CI: "1", APKTOOL_PATH: apktool, JADX_PATH: jadx },
    encoding: "utf8",
  });
  const elapsed = (Date.now() - t0) / 1000;
  assert.equal(r.status, 0, r.stderr);
  const order = fs.readFileSync(started, "utf8").trim().split("\n");
  assert.ok(order.includes("apktool-started") && order.includes("jadx-started"), "both tools started");
  // Sequential would be >=1.2s of tool time; concurrent should land well under.
  assert.ok(elapsed < 1.9, `expected concurrent runs, took ${elapsed.toFixed(2)}s`);
});
