const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { prepareInput, InputError } = require("../src/lib/apkInput");
const { readZipEntries, extractEntry, hasZipMagic } = require("../src/lib/zip");
const { tmpdir, rmrf, write, makeZip, makeApk } = require("./_helpers");

function fixture(t) {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  return { dir, file: (name, data) => write(path.join(dir, name), data), work: path.join(dir, "work") };
}
const apkOf = (marker) => makeApk([{ name: "assets/marker.txt", data: marker }]);
const markerOf = async (apkPath) => {
  const entries = await readZipEntries(apkPath);
  const e = entries.find((x) => x.name === "assets/marker.txt");
  const out = apkPath + ".marker";
  await extractEntry(apkPath, e, out);
  return fs.readFileSync(out, "utf8");
};

test("zip: lists and extracts deflated and stored entries with CRC verification", async (t) => {
  const { file, dir } = fixture(t);
  const payload = Buffer.from("hello ".repeat(5000));
  const zip = file("a.zip", makeZip([{ name: "d.txt", data: payload }, { name: "s.txt", data: "stored", store: true }, { name: "dir/empty", data: "" }]));
  const entries = await readZipEntries(zip);
  assert.deepEqual(entries.map((e) => e.name), ["d.txt", "s.txt", "dir/empty"]);
  await extractEntry(zip, entries[0], path.join(dir, "d.out"));
  await extractEntry(zip, entries[1], path.join(dir, "s.out"));
  await extractEntry(zip, entries[2], path.join(dir, "e.out"));
  assert.ok(fs.readFileSync(path.join(dir, "d.out")).equals(payload));
  assert.equal(fs.readFileSync(path.join(dir, "s.out"), "utf8"), "stored");
  assert.equal(fs.readFileSync(path.join(dir, "e.out"), "utf8"), "");
});

test("zip: a wrong CRC is detected rather than silently producing a bad APK", async (t) => {
  const { file, dir } = fixture(t);
  const zip = file("bad.zip", makeZip([{ name: "x.bin", data: "payload", badCrc: true }]));
  const [entry] = await readZipEntries(zip);
  await assert.rejects(extractEntry(zip, entry, path.join(dir, "x.out")), /CRC-32 mismatch/);
});

test("zip: hasZipMagic distinguishes zips from other files", async (t) => {
  const { file } = fixture(t);
  assert.equal(await hasZipMagic(file("a.apk", makeApk())), true);
  assert.equal(await hasZipMagic(file("b.apk", "dex\n035")), false);
  assert.equal(await hasZipMagic(file("c.apk", "")), false);
});

test("input: a plain APK passes through untouched", async (t) => {
  const { file, work } = fixture(t);
  const apk = file("app.apk", makeApk());
  const r = await prepareInput(apk, work);
  assert.deepEqual(r, { apkPath: apk, kind: "apk" });
  assert.ok(!fs.existsSync(work), "nothing is extracted for a plain APK");
});

test("input: XAPK — base chosen via manifest.json, config split ignored, noted as partial", async (t) => {
  const { file, work } = fixture(t);
  const xapk = file(
    "app.xapk",
    makeZip([
      { name: "manifest.json", data: JSON.stringify({ package_name: "com.acme.demo", split_apks: [{ file: "com.acme.demo.apk", id: "base" }, { file: "config.arm64_v8a.apk", id: "config.arm64_v8a" }] }) },
      { name: "config.arm64_v8a.apk", data: apkOf("SPLIT".repeat(5000)) }, // bigger than the base on purpose
      { name: "com.acme.demo.apk", data: apkOf("BASE") },
    ])
  );
  const r = await prepareInput(xapk, work);
  assert.equal(r.kind, "bundle");
  assert.equal(r.container, "XAPK");
  assert.equal(r.baseEntry, "com.acme.demo.apk");
  assert.equal(r.splitCount, 1);
  assert.equal(r.partial, true);
  assert.match(r.note, /other 1 split APK\(s\) were not analyzed/);
  assert.equal(await markerOf(r.apkPath), "BASE");
});

test("input: APKS — splits/base-master.apk beats ABI/density splits", async (t) => {
  const { file, work } = fixture(t);
  const apks = file(
    "app.apks",
    makeZip([
      { name: "toc.pb", data: "x" },
      { name: "splits/base-arm64_v8a.apk", data: apkOf("ARM".repeat(5000)) },
      { name: "splits/base-master.apk", data: apkOf("MASTER") },
      { name: "splits/base-xxhdpi.apk", data: apkOf("DPI".repeat(5000)) },
    ])
  );
  const r = await prepareInput(apks, work);
  assert.equal(r.baseEntry, "splits/base-master.apk");
  assert.equal(await markerOf(r.apkPath), "MASTER");
});

test("input: a universal.apk is preferred and is not reported as partial", async (t) => {
  const { file, work } = fixture(t);
  const apks = file("u.apks", makeZip([{ name: "toc.pb", data: "x" }, { name: "universal.apk", data: apkOf("UNI") }]));
  const r = await prepareInput(apks, work);
  assert.equal(r.baseEntry, "universal.apk");
  assert.equal(r.partial, false);
  assert.equal(await markerOf(r.apkPath), "UNI");
});

test("input: with no naming hints, the largest non-config APK wins", async (t) => {
  const { file, work } = fixture(t);
  const z = file(
    "mystery.apkm",
    makeZip([
      { name: "info.json", data: "{}" },
      { name: "split_config.en.apk", data: apkOf("EN".repeat(9000)) },
      { name: "small.apk", data: apkOf("S") },
      { name: "bigger.apk", data: apkOf("BIGGER".repeat(200)) },
    ])
  );
  const r = await prepareInput(z, work);
  assert.equal(r.baseEntry, "bigger.apk");
  assert.equal(r.container, "APKM");
});

test("input: an .aab is rejected with the bundletool remedy", async (t) => {
  const { file, work } = fixture(t);
  const aab = file("app.aab", makeZip([{ name: "BundleConfig.pb", data: "x" }, { name: "base/manifest/AndroidManifest.xml", data: "x" }]));
  await assert.rejects(prepareInput(aab, work), (e) => e instanceof InputError && /bundletool build-apks/.test(e.message) && /universal/.test(e.message));
});

test("input: non-APK inputs get specific, actionable errors", async (t) => {
  const { file, work } = fixture(t);
  const cases = [
    [file("plain.zip", makeZip([{ name: "readme.txt", data: "hi" }])), /neither AndroidManifest\.xml .* nor any \.apk/],
    [file("dex.apk", "dex\n035\0 rest"), /not an APK\/ZIP.*64 65 78 0a.*bare DEX/],
    [file("empty.apk", ""), /not an APK\/ZIP.*\(empty\)/],
    [file("html.apk", "<html><body>403 Forbidden</body></html>"), /not an APK\/ZIP/],
  ];
  for (const [f, re] of cases) await assert.rejects(prepareInput(f, work), (e) => e instanceof InputError && re.test(e.message), f);

  const whole = makeApk();
  await assert.rejects(prepareInput(file("trunc.apk", whole.subarray(0, whole.length - 30)), work), /not a readable ZIP\/APK: no ZIP end-of-central-directory/);
});

test("input: a corrupt base APK inside a bundle fails with the entry named", async (t) => {
  const { file, work } = fixture(t);
  const bundle = file("c.xapk", makeZip([{ name: "base.apk", data: apkOf("X"), badCrc: true }]));
  await assert.rejects(prepareInput(bundle, work), (e) => e instanceof InputError && /Couldn't extract base\.apk/.test(e.message) && /CRC-32/.test(e.message));
});
