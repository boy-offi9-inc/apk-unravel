const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { parseManifest } = require("../src/lib/manifest");
const { tmpdir, rmrf, write, MANIFEST } = require("./_helpers");

async function parsed(t, xml = MANIFEST) {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  write(path.join(dir, "AndroidManifest.xml"), xml);
  return parseManifest(dir);
}

test("parseManifest: package, version and SDK levels", async (t) => {
  const m = await parsed(t);
  assert.equal(m.packageName, "com.acme.demo");
  assert.equal(m.versionName, "1.2.3");
  assert.equal(String(m.versionCode), "42");
  assert.equal(String(m.minSdk), "24");
  assert.equal(String(m.targetSdk), "34");
});

test("parseManifest: flags dangerous permissions only", async (t) => {
  const m = await parsed(t);
  assert.deepEqual(m.dangerousPermissions, ["android.permission.CAMERA"]);
  assert.equal(m.permissions.length, 2);
});

test("parseManifest: exported = explicit true OR intent-filter without exported=false", async (t) => {
  const m = await parsed(t);
  const names = m.flaggedExported.map((c) => c.name).sort();
  assert.deepEqual(names, ["com.acme.demo.Boot", "com.acme.demo.DeepActivity", "com.acme.demo.Main"]);
  assert.ok(!names.includes("com.acme.demo.PrivateActivity"), "exported=false wins over an intent-filter");
  assert.ok(!names.includes("com.acme.demo.Svc"));
});

test("parseManifest: deep links carry reachability", async (t) => {
  const m = await parsed(t);
  const open = m.deepLinks.find((l) => l.scheme === "acme");
  const priv = m.deepLinks.find((l) => l.scheme === "acme-private");
  assert.equal(open.host, "open");
  assert.equal(open.reachable, true);
  assert.equal(priv.reachable, false);
});

test("parseManifest: security flags — debuggable, allowBackup default, explicit cleartext", async (t) => {
  const m = await parsed(t);
  const flags = m.security.flags.map((f) => f.flag).sort();
  assert.deepEqual(flags, ["allowBackup", "debuggable", "usesCleartextTraffic"]);
  const backup = m.security.flags.find((f) => f.flag === "allowBackup");
  assert.match(backup.detail, /not set \(defaults to true\)/);
});

test("parseManifest: absent cleartext attribute is not flagged; allowBackup=false clears its flag", async (t) => {
  const m = await parsed(
    t,
    `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="p"><application android:allowBackup="false"/></manifest>`
  );
  assert.equal(m.security.usesCleartextTraffic, false);
  assert.deepEqual(m.security.flags, []);
});

test("parseManifest: missing file gives an actionable error", async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  await assert.rejects(parseManifest(dir), /AndroidManifest\.xml not found/);
});
