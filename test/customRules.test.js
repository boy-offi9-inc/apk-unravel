const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { loadCustomRules, parseRuleSpec, RuleError } = require("../src/lib/customRules");
const { scanStrings, redactUrl } = require("../src/lib/stringScan");
const { tmpdir, rmrf, write } = require("./_helpers");

const spec = (s, i = 1) => parseRuleSpec(s, { origin: "t", index: i });

test("parseRuleSpec: name=/regex/flags, name=literal, unnamed, and '=' inside a regex", () => {
  const named = spec("internal=/ACME-[A-Z0-9]{8}/");
  assert.equal(named.name, "internal");
  assert.ok(named.regex.test("x ACME-AB12CD34 y"));

  const lit = spec("corp token=Hello.World");
  assert.equal(lit.name, "corp token");
  assert.ok(lit.regex.test("say HELLO.WORLD"), "literals are case-insensitive");
  lit.regex.lastIndex = 0;
  assert.ok(!lit.regex.test("HelloXWorld"), "literal dots are not wildcards");

  const unnamed = spec("/api_key=([a-z]+)/i", 3);
  assert.equal(unnamed.name, "rule 3", "a '/' before the first '=' means it's a pattern, not a name");
  assert.ok(unnamed.regex.test("API_KEY=abc"));

  assert.equal(spec("x=y=z").regex.source, "y=z");
});

test("parseRuleSpec: invalid and empty-matching patterns are rejected with the origin named", () => {
  assert.throws(() => spec("bad=/(unclosed/"), (e) => e instanceof RuleError && /invalid pattern/.test(e.message));
  assert.throws(() => spec("any=/a*/"), /matches the empty string/);
  assert.throws(() => spec("opt=/(foo)?/i"), /matches the empty string/);
  assert.throws(() => parseRuleSpec("name=  ", { origin: "--rule #2", index: 1 }), /--rule #2: empty pattern/);
});

test("loadCustomRules: --rule values are all loaded and split by kind", async () => {
  const { secretRules, matchRules } = await loadCustomRules({ rule: ["a=/AAA[0-9]+/", "b=literal"] });
  assert.deepEqual(secretRules.map((r) => r.name), ["a", "b"]);
  assert.deepEqual(matchRules, []);
});

test("loadCustomRules: .txt rules file with comments and blank lines; errors cite file:line", async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const good = write(path.join(dir, "rules.txt"), "# my rules\n\nvault=/hvs\\.[A-Za-z0-9]{20,}/\nstaging.acme.example\n");
  const { secretRules } = await loadCustomRules({ rulesFile: [good] });
  assert.deepEqual(secretRules.map((r) => r.name), ["vault", "rule 2"]);

  const bad = write(path.join(dir, "bad.txt"), "ok=/x+/\nbroken=/(/\n");
  await assert.rejects(loadCustomRules({ rulesFile: [bad] }), /bad\.txt:2: invalid pattern/);
});

test("loadCustomRules: JSON rules support regex/keyword, flags, kind and minEntropy", async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const file = write(
    path.join(dir, "rules.json"),
    JSON.stringify({
      rules: [
        { name: "vault", regex: "hvs\\.[A-Za-z0-9]{20,}", minEntropy: 3.5 },
        { name: "slashy", regex: "a/b[0-9]+", flags: "i" },
        { name: "staging host", keyword: "staging.acme.example", kind: "match" },
      ],
    })
  );
  const { secretRules, matchRules } = await loadCustomRules({ rulesFile: [file] });
  assert.deepEqual(secretRules.map((r) => r.name), ["vault", "slashy"]);
  assert.equal(secretRules[0].minEntropy, 3.5);
  assert.ok(secretRules[1].regex.test("A/B42"), "'/' inside a JSON regex needs no escaping");
  assert.deepEqual(matchRules.map((r) => r.name), ["staging host"]);
});

test("loadCustomRules: JSON validation errors are specific", async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const load = (name, content) => loadCustomRules({ rulesFile: [write(path.join(dir, name), typeof content === "string" ? content : JSON.stringify(content))] });
  await assert.rejects(load("a.json", "{nope"), /not valid JSON/);
  await assert.rejects(load("b.json", { foo: 1 }), /array of rules/);
  await assert.rejects(load("c.json", [{ regex: "x+" }]), /"name" is required/);
  await assert.rejects(load("d.json", [{ name: "n" }]), /exactly one of "regex" or "keyword"/);
  await assert.rejects(load("e.json", [{ name: "n", regex: "a", keyword: "b" }]), /exactly one of/);
  await assert.rejects(load("f.json", [{ name: "n", regex: "a+", flags: "x" }]), /flags may only contain/);
  await assert.rejects(load("g.json", [{ name: "n", regex: "a+", kind: "bogus" }]), /kind must be/);
  await assert.rejects(load("h.json", [{ name: "n", regex: "a+", minEntropy: 99 }]), /minEntropy/);
  await assert.rejects(loadCustomRules({ rulesFile: [path.join(dir, "missing.json")] }), /Can't read rules file/);
});

test("loadCustomRules: --grep-file lines become match rules; commas in regexes survive", async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const f = write(path.join(dir, "words.txt"), "# wordlist\nfirebase\n/a{1,3}b/\n\n");
  const { matchRules, secretRules } = await loadCustomRules({ grepFile: [f] });
  assert.deepEqual(secretRules, []);
  assert.deepEqual(matchRules.map((r) => r.name), ["firebase", "/a{1,3}b/"]);
  assert.ok(matchRules[1].regex.test("xaab"));
});

test("scanStrings: custom secret rules are reported masked, labelled, and not placeholder-filtered", async (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  write(path.join(root, "sources/A.java"), `String a = "ACME-AB12CD34"; String b = "ACME-EXAMPLE1"; String c = "ACME-AB12CD34";`);
  const { secretRules } = await loadCustomRules({ rule: ["internal=/ACME-[A-Z0-9]{8}/"] });
  const res = await scanStrings(root, { secretRules });
  const found = res.potentialSecrets.filter((s) => s.label === "Custom: internal");
  assert.equal(found.length, 2, "ACME-EXAMPLE1 contains the word EXAMPLE but a user's own rule isn't second-guessed");
  const real = found.find((s) => s.match === "ACME-AB12CD34");
  assert.equal(real.occurrences, 2);
  assert.notEqual(real.masked, real.match);
  assert.deepEqual(res.rules.secretRules, ["internal"]);
});

test("scanStrings: minEntropy drops low-entropy custom hits", async (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  write(path.join(root, "sources/B.java"), `"tok_aaaaaaaaaaaa" "tok_q8Zr3LmX0pTb"`);
  const { secretRules } = await loadCustomRules({ rule: [] , rulesFile: [write(path.join(root, "r.json"), JSON.stringify([{ name: "tok", regex: "tok_[A-Za-z0-9]{12}", minEntropy: 3 }]))] });
  const res = await scanStrings(root, { secretRules });
  assert.deepEqual(res.potentialSecrets.map((s) => s.match), ["tok_q8Zr3LmX0pTb"]);
  assert.ok(res.potentialSecrets[0].entropy >= 3);
});

test("scanStrings: builtinSecrets:false reports only the user's rules", async (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  write(path.join(root, "sources/C.java"), `"AIzaSyA1234567890abcdefghijklmnopqrstuA" "ACME-AB12CD34"`);
  const { secretRules } = await loadCustomRules({ rule: ["internal=/ACME-[A-Z0-9]{8}/"] });
  const both = await scanStrings(root, { secretRules });
  const only = await scanStrings(root, { secretRules, builtinSecrets: false });
  assert.deepEqual(both.potentialSecrets.map((s) => s.label).sort(), ["Custom: internal", "Google API key"]);
  assert.deepEqual(only.potentialSecrets.map((s) => s.label), ["Custom: internal"]);
  assert.equal(only.rules.builtinSecrets, false);
});

test("URLs containing a custom-rule secret are masked in the URL list", async (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  write(path.join(root, "sources/D.java"), `String u = "https://api.acme.example/v1?auth=ACME-AB12CD34";`);
  const { secretRules } = await loadCustomRules({ rule: ["internal=/ACME-[A-Z0-9]{8}/"] });
  const res = await scanStrings(root, { secretRules });
  assert.ok(res.urls.every((u) => !u.includes("ACME-AB12CD34")));
  assert.ok(redactUrl("https://x.example/?k=ACME-AB12CD34", secretRules).includes("…"));
  assert.equal(redactUrl("https://x.example/?k=ACME-AB12CD34"), "https://x.example/?k=ACME-AB12CD34", "without the rule nothing is masked");
});
