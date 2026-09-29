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
