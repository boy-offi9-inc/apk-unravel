const test = require("node:test");
const assert = require("node:assert/strict");
const { splitArgs } = require("../src/lib/shellSplit");

test("splitArgs: whitespace, quotes and escapes", () => {
  assert.deepEqual(splitArgs("--threads-count 1 --no-imports"), ["--threads-count", "1", "--no-imports"]);
  assert.deepEqual(splitArgs("  a   b\tc\n"), ["a", "b", "c"]);
  assert.deepEqual(splitArgs(`--rename-flags "valid, printable"`), ["--rename-flags", "valid, printable"]);
  assert.deepEqual(splitArgs(`--x 'single $quoted "inner"'`), ["--x", `single $quoted "inner"`]);
  assert.deepEqual(splitArgs(`--x "say \\"hi\\""`), ["--x", 'say "hi"']);
  assert.deepEqual(splitArgs("path\\ with\\ spaces"), ["path with spaces"]);
});

test("splitArgs: empty quoted argument is preserved, empty input is empty", () => {
  assert.deepEqual(splitArgs(`a "" b`), ["a", "", "b"]);
  assert.deepEqual(splitArgs(""), []);
  assert.deepEqual(splitArgs("   "), []);
});

test("splitArgs: nothing is expanded or executed", () => {
  assert.deepEqual(splitArgs("$(touch /tmp/pwn) `id` ; rm -rf *"), ["$(touch", "/tmp/pwn)", "`id`", ";", "rm", "-rf", "*"]);
});

test("splitArgs: unterminated quote / trailing backslash are errors", () => {
  assert.throws(() => splitArgs(`--x "oops`), /unterminated double quote/);
  assert.throws(() => splitArgs(`--x 'oops`), /unterminated single quote/);
  assert.throws(() => splitArgs("oops\\"), /trailing backslash/);
});
