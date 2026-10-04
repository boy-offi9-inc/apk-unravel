// End-to-end: runs the real CLI against fake apktool/jadx binaries.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { tmpdir, rmrf, write, fakeBin, makeApk, MANIFEST } = require("./_helpers");

const BIN = path.join(__dirname, "..", "bin", "apk-unravel.js");
const posix = { skip: process.platform === "win32" && "needs a POSIX shell for the fake binaries" };

function setup(t) {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const manifestSrc = write(path.join(dir, "manifest.src.xml"), MANIFEST);
  const argsFile = path.join(dir, "apktool-args.txt");
  const apktool = fakeBin(
    path.join(dir, "apktool"),
    // apktool d -f -o OUT [-s] APK
    `OUT=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && OUT="$2"; shift; done
echo "$ORIG_ARGS" > "${argsFile}"
mkdir -p "$OUT"; cp "${manifestSrc}" "$OUT/AndroidManifest.xml"`
  );
  // wrapper so we can capture the exact argv apk-unravel passed to apktool
  const wrapper = fakeBin(path.join(dir, "apktool-wrap"), `ORIG_ARGS="$*" exec "${apktool}" "$@"`);
  const jadx = fakeBin(
    path.join(dir, "jadx"),
    `mkdir -p "$2/sources/com/acme"; echo 'class A { String u = "https://api.acme.example"; }' > "$2/sources/com/acme/A.java"`
  );
  const apk = write(path.join(dir, "app.apk"), makeApk());
  const env = { ...process.env, CI: "1", APKTOOL_PATH: wrapper, JADX_PATH: jadx };
  const run = (...args) => spawnSync(process.execPath, [BIN, "decompile", apk, "-o", path.join(dir, "out"), ...args], { env, encoding: "utf8" });
  return { dir, argsFile, run };
}

test("full run writes report.json/report.md and exits 0", posix, (t) => {
  const { dir, run } = setup(t);
  const r = run();
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.ok(fs.existsSync(path.join(dir, "out", "report.json")));
  assert.ok(fs.existsSync(path.join(dir, "out", "report.md")));
  assert.match(r.stdout, /com\.acme\.demo/);
});

test("smali is ON by default: apktool is NOT given -s (regression)", posix, (t) => {
  const { argsFile, run } = setup(t);
  assert.equal(run().status, 0);
  const args = fs.readFileSync(argsFile, "utf8").trim().split(/\s+/);
  assert.ok(!args.includes("-s"), `unexpected -s in: ${args.join(" ")}`);
});

test("--no-smali passes -s to apktool", posix, (t) => {
  const { argsFile, run } = setup(t);
  assert.equal(run("--no-smali").status, 0);
  assert.ok(fs.readFileSync(argsFile, "utf8").trim().split(/\s+/).includes("-s"));
});

test("--jadx-only still produces a report (manifest read from jadx output)", posix, (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const jadx = fakeBin(
    path.join(dir, "jadx"),
    `mkdir -p "$2/sources" "$2/resources"; cp "${write(path.join(dir, "m.xml"), MANIFEST)}" "$2/resources/AndroidManifest.xml"`
  );
  const apk = write(path.join(dir, "app.apk"), makeApk());
  const r = spawnSync(process.execPath, [BIN, "decompile", apk, "--jadx-only", "-o", path.join(dir, "out")], {
    env: { ...process.env, CI: "1", JADX_PATH: jadx },
    encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const report = JSON.parse(fs.readFileSync(path.join(dir, "out", "report.json"), "utf8"));
  assert.equal(report.manifestSource, "jadx");
  assert.equal(report.manifest.packageName, "com.acme.demo");
});

test("--apktool-only with --jadx-only is rejected", posix, (t) => {
  const { run } = setup(t);
  const r = run("--apktool-only", "--jadx-only");
  assert.equal(r.status, 1);
  assert.match(r.stderr, /can't be combined/);
});

test("--json: stdout is pure JSON, secrets masked, warnings on stderr", posix, (t) => {
  const { dir, run } = setup(t);
  write(path.join(dir, "unused"), "");
  const r = run("--json", "--strings");
  assert.equal(r.status, 0, r.stderr);
  const parsed = JSON.parse(r.stdout); // throws if any banner/spinner text leaked into stdout
  assert.equal(parsed.manifest.packageName, "com.acme.demo");
  for (const s of parsed.stringScan.potentialSecrets) assert.ok(!("match" in s));
});

test("--quiet prints only the report.json path", posix, (t) => {
  const { dir, run } = setup(t);
  const r = run("--quiet");
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), path.join(dir, "out", "report.json"));
});

test("missing APK: error on stderr, nothing on stdout, exit 1", (t) => {
  const r = spawnSync(process.execPath, [BIN, "decompile", "/no/such/file.apk"], { env: { ...process.env, CI: "1" }, encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /APK not found/);
  assert.ok(!/APK not found/.test(r.stdout));
});

test("XAPK input: tools run on the extracted base APK and the report says so", posix, (t) => {
  const { dir, argsFile, run } = setup(t);
  const { makeZip } = require("./_helpers");
  const xapk = write(
    path.join(dir, "bundle.xapk"),
    makeZip([
      { name: "manifest.json", data: JSON.stringify({ package_name: "com.acme.demo", split_apks: [{ file: "base.apk", id: "base" }, { file: "config.xxhdpi.apk", id: "config.xxhdpi" }] }) },
      { name: "base.apk", data: require("./_helpers").makeApk() },
      { name: "config.xxhdpi.apk", data: require("./_helpers").makeApk() },
    ])
  );
  const r = spawnSync(process.execPath, [BIN, "decompile", xapk, "-o", path.join(dir, "out2")], {
    env: { ...process.env, CI: "1", APKTOOL_PATH: path.join(dir, "apktool-wrap"), JADX_PATH: path.join(dir, "jadx") },
    encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const apktoolArgs = fs.readFileSync(argsFile, "utf8").trim().split(/\s+/);
  assert.equal(apktoolArgs[apktoolArgs.length - 1], path.join(dir, "out2", "input", "base.apk"));
  assert.match(r.stderr, /other 1 split APK\(s\) were not analyzed/);
  const report = JSON.parse(fs.readFileSync(path.join(dir, "out2", "report.json"), "utf8"));
  assert.equal(report.input.kind, "bundle");
  assert.equal(report.input.baseEntry, "base.apk");
  assert.match(fs.readFileSync(path.join(dir, "out2", "report.md"), "utf8"), /\*\*Input:\*\* XAPK bundle — analyzed `base\.apk`/);
});

test("garbage input: clear error on stderr, exit 1, no tools run", posix, (t) => {
  const { dir, argsFile, run } = setup(t);
  const bad = write(path.join(dir, "download.apk"), "<html>403 Forbidden</html>");
  const r = spawnSync(process.execPath, [BIN, "decompile", bad, "-o", path.join(dir, "out3")], {
    env: { ...process.env, CI: "1", APKTOOL_PATH: path.join(dir, "apktool-wrap"), JADX_PATH: path.join(dir, "jadx") },
    encoding: "utf8",
  });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /not an APK\/ZIP/);
  assert.ok(!fs.existsSync(argsFile), "apktool must not have been invoked");
});
