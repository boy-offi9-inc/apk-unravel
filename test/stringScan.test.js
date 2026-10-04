const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { splitKeywords, parseKeywords, scanStrings } = require("../src/lib/stringScan");
const { writeStringsExport } = require("../src/lib/stringsExport");
const { tmpdir, rmrf, write } = require("./_helpers");

test("splitKeywords: plain terms, whitespace and empty segments", () => {
  assert.deepEqual(splitKeywords("plain , spaced ,,x"), ["plain", "spaced", "x"]);
  assert.deepEqual(splitKeywords(""), []);
});

test("splitKeywords: keeps commas inside /regex/ literals (was broken)", () => {
  assert.deepEqual(splitKeywords("/a{1,3}/,foo"), ["/a{1,3}/", "foo"]);
  assert.deepEqual(splitKeywords("/[,]/g , x"), ["/[,]/g", "x"]);
  assert.deepEqual(splitKeywords("firebase,MyCo,/api\\.internal\\.[a-z]+/i"), [
    "firebase",
    "MyCo",
    "/api\\.internal\\.[a-z]+/i",
  ]);
});

test("splitKeywords: an unterminated /regex falls back to comma splitting", () => {
  assert.deepEqual(splitKeywords("/unterminated,foo"), ["/unterminated", "foo"]);
});

test("parseKeywords: reports invalid regex without dropping valid terms", () => {
  const { compiled, invalid } = parseKeywords("ok,/(unclosed/,also.ok");
  assert.equal(invalid.length, 1);
  assert.equal(invalid[0].keyword, "/(unclosed/");
  assert.deepEqual(
    compiled.map((c) => c.keyword),
    ["ok", "also.ok"]
  );
});

test("parseKeywords: literal terms are case-insensitive and regex-escaped", () => {
  const { compiled } = parseKeywords("api.example.com");
  assert.ok(compiled[0].regex.test("see API.EXAMPLE.COM"));
  compiled[0].regex.lastIndex = 0;
  assert.ok(!compiled[0].regex.test("apiXexampleXcom"));
});

test("scanStrings: finds, masks-ready, dedups secrets and ignores placeholders", async (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  const key = "AIzaSyA1234567890abcdefghijklmnopqrstuvw";
  write(path.join(root, "sources/A.java"), `String k = "${key}"; String u = "https://api.acme.example/v1";`);
  write(path.join(root, "sources/B.java"), `String again = "${key}";`);
  write(path.join(root, "sources/C.java"), `String p = "api_key = 'YOUR_API_KEY_HERE_0123456789'";`);
  write(path.join(root, "sources/blob.bin"), key); // extension not scanned

  const result = await scanStrings(root, { keywords: parseKeywords("acme").compiled });

  assert.equal(result.potentialSecrets.length, 1, "same value in two files is one finding");
  const [secret] = result.potentialSecrets;
  assert.equal(secret.label, "Google API key");
  assert.equal(secret.occurrences, 2);
  assert.equal(secret.files.length, 2);
  assert.notEqual(secret.masked, secret.match);
  assert.ok(secret.masked.includes("…") && !secret.masked.includes("abcdefghijklmnopq"));
  assert.ok(result.urls.includes("https://api.acme.example/v1"));
  assert.ok(result.keywordMatches.length >= 1);
});

test("writeStringsExport: JSON export never contains unmasked secret values", async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const scan = {
    urls: [],
    keywordMatches: [],
    potentialSecrets: [{ label: "x", match: "SUPERSECRETVALUE1234567890", masked: "SUPERS…7890", occurrences: 1, files: ["a"] }],
  };
  const out = await writeStringsExport(scan, path.join(dir, "f.json"));
  const text = require("fs").readFileSync(out, "utf8");
  assert.ok(!text.includes("SUPERSECRETVALUE1234567890"));
  assert.ok(text.includes("SUPERS…7890"));
  const csv = await writeStringsExport(scan, path.join(dir, "f.csv"));
  assert.ok(!require("fs").readFileSync(csv, "utf8").includes("SUPERSECRETVALUE1234567890"));
});

const { analyzeUrls } = require("../src/lib/urlAnalysis");
const { shannonEntropy, redactUrl } = require("../src/lib/stringScan");

test("scanStrings: detects modern provider tokens", async (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  const gh = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
  const sg = "SG." + "abcdefghijklmnop" + "." + "qrstuvwxyz0123456789ABCD";
  const twilio = "SK" + "0123456789abcdef0123456789abcdef";
  const github2 = "github_pat_" + "11ABCDEFG0abcdefghij_KLMNOPQRSTUV";
  write(path.join(root, "sources/T.java"), `String a = "${gh}"; String b = "${sg}"; String c = "${twilio}"; String d = "${github2}";`);
  const { potentialSecrets } = await scanStrings(root);
  const labels = potentialSecrets.map((s) => s.label).sort();
  assert.deepEqual(labels, ["GitHub fine-grained token", "GitHub token", "SendGrid API key", "Twilio API key SID"]);
});

test("scanStrings: entropy filter drops identifiers but keeps random-looking values", async (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  write(
    path.join(root, "sources/G.java"),
    [
      `String h = "auth_token = 'authorization_header_name_value'";`, // readable constant: no digits, low variety
      `String k = "api_key = 'com_acme_config_option_name'";`,
      `String real = "api_key = 'q8Zr3LmX0pTb7VnC5dKe2Wy9'";`,
    ].join("\n")
  );
  const { potentialSecrets } = await scanStrings(root);
  assert.equal(potentialSecrets.length, 1);
  assert.match(potentialSecrets[0].match, /q8Zr3LmX0pTb7VnC5dKe2Wy9/);
  assert.ok(potentialSecrets[0].entropy >= 3, "generic findings carry their entropy");
});

test("shannonEntropy: sanity", () => {
  assert.equal(shannonEntropy(""), 0);
  assert.equal(shannonEntropy("aaaaaaaa"), 0);
  assert.ok(shannonEntropy("q8Zr3LmX0pTb7VnC") > 3.5);
});

test("URLs containing a secret are redacted in the URL list but the secret is still reported", async (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  // Built at runtime: a contiguous webhook-shaped literal in the repo trips GitHub push protection (even though this one is fake).
  const hook = ["https://hooks.slack.com/services", "T01234ABC", "B01234DEF", "abcdEFGH1234ijklMNOP5678"].join("/");
  write(path.join(root, "sources/W.java"), `String w = "${hook}"; String ok = "https://api.acme.example/v1";`);
  const res = await scanStrings(root);
  assert.ok(!res.urls.some((u) => u.includes("abcdEFGH1234ijklMNOP5678")), "webhook secret must not appear in the URL list");
  assert.ok(res.urls.includes("https://api.acme.example/v1"));
  assert.equal(res.potentialSecrets.find((s) => s.label === "Slack webhook URL").match, hook);
  assert.ok(!redactUrl("https://api.acme.example/v1").includes("…"), "clean URLs pass through untouched");
});

test("scanStrings: URL cap is reported instead of silently truncating", async (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  const many = Array.from({ length: 30 }, (_, i) => `"https://h${i}.example/p"`).join(",");
  write(path.join(root, "sources/U.java"), `String[] u = {${many}};`);
  const capped = await scanStrings(root, { maxUrls: 10 });
  assert.equal(capped.urls.length, 10);
  assert.equal(capped.urlsTruncated, true);
  const full = await scanStrings(root);
  assert.equal(full.urls.length, 30);
  assert.equal(full.urlsTruncated, false);
});

test("analyzeUrls: groups by host, flags cleartext/IP/cloud endpoints, ignores namespace and local noise", () => {
  const a = analyzeUrls([
    "https://api.acme.example/a",
    "https://api.acme.example/b",
    "http://legacy.acme.example/x",
    "http://schemas.android.com/apk/res/android",
    "http://www.w3.org/2001/XMLSchema",
    "http://10.0.2.2:8080/emulator",
    "http://localhost:3000/dev",
    "http://203.0.113.7:8080/api",
    "https://acme-prod-default-rtdb.firebaseio.com/",
    "https://acme-assets.s3.us-east-1.amazonaws.com/img.png",
    "https://storage.googleapis.com/acme-bucket/f",
    "https://acme.blob.core.windows.net/c",
    "not a url",
  ]);
  assert.equal(a.domains[0].host, "api.acme.example");
  assert.equal(a.domains[0].count, 2);
  assert.ok(!a.domains.some((d) => d.host === "schemas.android.com" || d.host === "www.w3.org"));
  assert.deepEqual(a.cleartextUrls.sort(), ["http://203.0.113.7:8080/api", "http://legacy.acme.example/x"]);
  assert.deepEqual(a.ipUrls, ["http://203.0.113.7:8080/api"]);
  assert.deepEqual(a.notable.map((n) => n.kind).sort(), ["aws-s3-bucket", "azure-blob-storage", "firebase-realtime-db", "gcs-bucket"]);
});

const { buildExcluder } = require("../src/lib/stringScan");

function libTree(t) {
  const root = tmpdir();
  t.after(() => rmrf(root));
  const key = (n) => `String k = "AIzaSyA1234567890abcdefghijklmnopqrstu${n}";`;
  write(path.join(root, "sources/com/acme/App.java"), key("A")); // app code
  write(path.join(root, "sources/androidx/core/X.java"), key("B")); // third-party
  write(path.join(root, "sources/com/google/android/gms/Y.java"), key("C")); // third-party
  write(path.join(root, "sources/com/acme/androidx/Own.java"), key("D")); // app's OWN 'androidx' package: must survive
  write(path.join(root, "sources/com/vendor/sdk/Z.java"), key("E"));
  write(path.join(root, "smali_classes2/kotlin/K.smali"), key("F")); // apktool layout
  write(path.join(root, "resources/res/values/strings.xml"), key("G")); // resources are never skipped
  return root;
}
const files = (res) => res.potentialSecrets.flatMap((s) => s.files.map((f) => f.split(path.sep).join("/"))).sort();

test("scanStrings: without flags everything is scanned", async (t) => {
  const res = await scanStrings(libTree(t));
  assert.equal(res.potentialSecrets.length, 7);
  assert.equal(res.excluded.skippedDirs, 0);
});

test("scanStrings --skip-libs: drops well-known libraries in both jadx and smali layouts, keeps app code", async (t) => {
  const res = await scanStrings(libTree(t), { skipLibs: true });
  assert.deepEqual(files(res), [
    "resources/res/values/strings.xml",
    "sources/com/acme/App.java",
    "sources/com/acme/androidx/Own.java",
    "sources/com/vendor/sdk/Z.java",
  ]);
  assert.equal(res.excluded.libs, true);
  assert.equal(res.excluded.skippedDirs, 3);
});

test("scanStrings --exclude-pkg: accepts dotted or slashed names, combines with --skip-libs", async (t) => {
  const dotted = await scanStrings(libTree(t), { excludePackages: ["com.vendor.sdk"] });
  assert.ok(!files(dotted).includes("sources/com/vendor/sdk/Z.java"));
  assert.ok(files(dotted).includes("sources/androidx/core/X.java"), "libs stay in unless --skip-libs is also given");

  const both = await scanStrings(libTree(t), { skipLibs: true, excludePackages: ["com/vendor/sdk/"] });
  assert.equal(both.potentialSecrets.length, 3);
  assert.deepEqual(both.excluded.packages, ["com/vendor/sdk"]);
});

test("buildExcluder: only matches a package folder directly under a code root", () => {
  const ex = buildExcluder({ skipLibs: true });
  assert.equal(ex("sources/androidx"), true);
  assert.equal(ex("smali_classes3/androidx"), true);
  assert.equal(ex(path.join("sources", "com", "google", "android", "gms")), true);
  assert.equal(ex("sources/com/acme/androidx"), false);
  assert.equal(ex("resources/androidx"), false);
  assert.equal(ex("sources"), false);
  assert.equal(buildExcluder()("sources/androidx"), false);
});
