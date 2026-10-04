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

test("permissions: tiers separate runtime prompts from special-access grants", async (t) => {
  const { permissionTier, DANGEROUS_PERMISSIONS } = require("../src/lib/permissions");
  for (const name of [
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.ACTIVITY_RECOGNITION",
  ]) {
    assert.equal(permissionTier(name), "runtime", name);
    assert.ok(DANGEROUS_PERMISSIONS.has(name), name);
  }
  for (const name of ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.PACKAGE_USAGE_STATS", "android.permission.WRITE_SETTINGS"]) {
    assert.equal(permissionTier(name), "special", name);
    assert.ok(DANGEROUS_PERMISSIONS.has(name), name);
  }
  assert.equal(permissionTier("android.permission.INTERNET"), "normal");
  assert.ok(!DANGEROUS_PERMISSIONS.has("android.permission.INTERNET"));
});

test("parseManifest: each permission carries its tier", async (t) => {
  const m = await parsed(
    t,
    `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="p">
       <uses-permission android:name="android.permission.CAMERA"/>
       <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
       <uses-permission android:name="android.permission.INTERNET"/>
       <application/></manifest>`
  );
  const tiers = Object.fromEntries(m.permissions.map((p) => [p.name.split(".").pop(), p.tier]));
  assert.deepEqual(tiers, { CAMERA: "runtime", SYSTEM_ALERT_WINDOW: "special", INTERNET: "normal" });
  assert.equal(m.dangerousPermissions.length, 2);
});

const GUARDED_MANIFEST = `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.acme.g" android:sharedUserId="com.acme.shared">
  <permission android:name="com.acme.g.WEAK" android:protectionLevel="normal"/>
  <permission android:name="com.acme.g.STRONG" android:protectionLevel="signature"/>
  <permission android:name="com.acme.g.NOLEVEL"/>
  <application android:testOnly="true">
    <activity android:name=".Main" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
    </activity>
    <activity-alias android:name=".Alias" android:targetActivity=".Main" android:exported="true"/>
    <activity android:name=".Open" android:exported="true"/>
    <service android:name=".Guarded" android:exported="true" android:permission="com.acme.g.STRONG"/>
    <service android:name=".WeakGuarded" android:exported="true" android:permission="com.acme.g.WEAK"/>
    <service android:name=".NoLevelGuarded" android:exported="true" android:permission="com.acme.g.NOLEVEL"/>
    <receiver android:name=".SystemGuarded" android:exported="true" android:permission="android.permission.BIND_DEVICE_ADMIN"/>
    <provider android:name=".HalfGuarded" android:authorities="a" android:exported="true" android:readPermission="com.acme.g.STRONG"/>
    <provider android:name=".FullGuarded" android:authorities="b" android:exported="true" android:readPermission="com.acme.g.STRONG" android:writePermission="com.acme.g.STRONG"/>
  </application>
</manifest>`;

test("parseManifest: components are classified by permission guard", async (t) => {
  const m = await parsed(t, GUARDED_MANIFEST);
  const byName = Object.fromEntries(m.flaggedExported.map((c) => [c.name, c]));

  assert.equal(byName[".Main"].launcher, true);
  assert.equal(byName[".Open"].guarded, false);
  assert.equal(byName[".Guarded"].guarded, true);
  assert.equal(byName[".Guarded"].weakGuard, false);
  assert.equal(byName[".WeakGuarded"].weakGuard, true, "custom permission with protectionLevel=normal is no real guard");
  assert.equal(byName[".NoLevelGuarded"].weakGuard, true, "missing protectionLevel defaults to normal");
  assert.equal(byName[".SystemGuarded"].weakGuard, false, "system permissions aren't declared here, so aren't judged weak");
  assert.equal(byName[".HalfGuarded"].guarded, false, "read-only permission leaves writes open");
  assert.equal(byName[".FullGuarded"].guarded, true);
});

test("parseManifest: activity-alias is analysed like an activity", async (t) => {
  const m = await parsed(t, GUARDED_MANIFEST);
  const alias = m.flaggedExported.find((c) => c.name === ".Alias");
  assert.equal(alias.kind, "activityAliases");
  assert.equal(m.components.activityAliases[0].targetActivity, ".Main");
});

test("parseManifest: unguardedExported excludes launcher and properly guarded components", async (t) => {
  const m = await parsed(t, GUARDED_MANIFEST);
  assert.deepEqual(
    m.unguardedExported.map((c) => c.name).sort(),
    [".Alias", ".HalfGuarded", ".NoLevelGuarded", ".Open", ".WeakGuarded"]
  );
  assert.ok(m.flaggedExported.length > m.unguardedExported.length, "flaggedExported still lists everything");
});

test("parseManifest: testOnly and sharedUserId are flagged", async (t) => {
  const m = await parsed(t, GUARDED_MANIFEST);
  const flags = m.security.flags.map((f) => f.flag);
  assert.ok(flags.includes("testOnly"));
  assert.ok(flags.includes("sharedUserId"));
  assert.equal(m.security.sharedUserId, "com.acme.shared");
});

function nscManifest(ref = "@xml/nsc") {
  return `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="p"><application android:networkSecurityConfig="${ref}"/></manifest>`;
}
async function withNsc(t, nscXml, ref) {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  write(path.join(dir, "AndroidManifest.xml"), nscManifest(ref));
  if (nscXml !== null) write(path.join(dir, "res/xml/nsc.xml"), nscXml);
  return parseManifest(dir);
}

test("network security config: base cleartext + user CA trust are flagged", async (t) => {
  const m = await withNsc(
    t,
    `<network-security-config>
       <base-config cleartextTrafficPermitted="true"><trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors></base-config>
     </network-security-config>`
  );
  const flags = m.security.flags.map((f) => f.flag);
  assert.ok(flags.includes("networkSecurityConfigCleartext"));
  assert.ok(flags.includes("trustsUserCertificates"));
  assert.equal(m.security.networkSecurity.found, true);
});

test("network security config: per-domain cleartext is listed; pinning and debug-overrides are recorded", async (t) => {
  const m = await withNsc(
    t,
    `<network-security-config>
       <domain-config cleartextTrafficPermitted="true"><domain includeSubdomains="true">legacy.acme.example</domain></domain-config>
       <domain-config><domain>api.acme.example</domain><pin-set><pin digest="SHA-256">AAAA=</pin></pin-set></domain-config>
       <debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>
     </network-security-config>`
  );
  const dom = m.security.flags.find((f) => f.flag === "networkSecurityConfigCleartextDomains");
  assert.match(dom.detail, /legacy\.acme\.example/);
  assert.ok(!m.security.flags.some((f) => f.flag === "trustsUserCertificates"), "debug-overrides trust must not count as production trust");
  assert.equal(m.security.networkSecurity.hasPinning, true);
  assert.equal(m.security.networkSecurity.hasDebugOverrides, true);
});

test("network security config: a locked-down config raises no flags", async (t) => {
  const m = await withNsc(
    t,
    `<network-security-config><base-config cleartextTrafficPermitted="false"><trust-anchors><certificates src="system"/></trust-anchors></base-config></network-security-config>`
  );
  assert.deepEqual(m.security.flags.filter((f) => /networkSecurity|trustsUser/.test(f.flag)), []);
});

test("network security config: missing referenced file is reported, not fatal", async (t) => {
  const m = await withNsc(t, null);
  assert.equal(m.security.networkSecurity.found, false);
  assert.ok(m.security.flags.some((f) => f.flag === "networkSecurityConfigUnreadable"));
});

test("report.md: exported table shows exposure and guard, launcher marked expected", async (t) => {
  const { renderMarkdown } = require("../src/lib/report");
  const m = await parsed(t, GUARDED_MANIFEST);
  const md = renderMarkdown({
    apkFile: "a.apk", generatedAt: "now", manifest: m, appIdentity: null, stringScan: null, nativeLibs: null,
    outputPaths: { apktool: "/x", jadx: null },
  });
  assert.match(md, /Exported \/ intent-filtered components \(\d+, 5 unguarded\)/);
  assert.match(md, /launcher entry point \(expected\)/);
  assert.match(md, /no real protection/);
});
