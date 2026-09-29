const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { resolveAppIdentity } = require("../src/lib/appIdentity");
const { tmpdir, rmrf, write } = require("./_helpers");

const ADAPTIVE = (fg) =>
  `<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android"><background android:drawable="@color/bg"/><foreground android:drawable="${fg}"/></adaptive-icon>`;

function project(t) {
  const root = tmpdir();
  t.after(() => rmrf(root));
  write(path.join(root, "res/values/strings.xml"), `<resources><string name="app_name">Acme Demo</string></resources>`);
  return { root, out: path.join(root, "out") };
}

test("resolves @string label and picks the highest-density raster icon", async (t) => {
  const { root, out } = project(t);
  write(path.join(root, "res/mipmap-hdpi/ic_launcher.png"), "hd");
  write(path.join(root, "res/mipmap-xxhdpi/ic_launcher.png"), "xxhd");
  write(path.join(root, "res/mipmap-anydpi-v26/ic_launcher.xml"), ADAPTIVE("@mipmap/ic_fg"));
  fs.mkdirSync(out);

  const id = await resolveAppIdentity(root, out, "@string/app_name", "@mipmap/ic_launcher");
  assert.equal(id.label, "Acme Demo");
  assert.equal(path.basename(id.iconOutputPath), "icon.png");
  assert.equal(fs.readFileSync(id.iconOutputPath, "utf8"), "xxhd");
});

test("adaptive-only icon resolves through its <foreground> raster", async (t) => {
  const { root, out } = project(t);
  write(path.join(root, "res/mipmap-anydpi-v26/ic_launcher.xml"), ADAPTIVE("@mipmap/ic_fg"));
  write(path.join(root, "res/mipmap-xxhdpi/ic_fg.webp"), "fgwebp");
  fs.mkdirSync(out);

  const id = await resolveAppIdentity(root, out, "@string/app_name", "@mipmap/ic_launcher");
  assert.equal(path.basename(id.iconOutputPath), "icon.webp");
  assert.equal(fs.readFileSync(id.iconOutputPath, "utf8"), "fgwebp");
});

test("XML-only icon is reported but never copied out as icon.xml", async (t) => {
  const { root, out } = project(t);
  write(path.join(root, "res/drawable/ic_launcher.xml"), `<vector xmlns:android="http://schemas.android.com/apk/res/android"/>`);
  fs.mkdirSync(out);

  const id = await resolveAppIdentity(root, out, "@string/app_name", "@drawable/ic_launcher");
  assert.equal(id.iconOutputPath, null);
  assert.ok(id.iconSourcePath.endsWith("ic_launcher.xml"));
  assert.deepEqual(fs.readdirSync(out), []);
});

test("unresolvable label ref falls back to the raw reference", async (t) => {
  const { root, out } = project(t);
  fs.mkdirSync(out);
  const id = await resolveAppIdentity(root, out, "@string/does_not_exist", undefined);
  assert.equal(id.label, "@string/does_not_exist");
  assert.equal(id.iconOutputPath, null);
});
