const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { runJadx } = require("../src/lib/runners/jadx");
const { tmpdir, rmrf, fakeBin } = require("./_helpers");

const posix = { skip: process.platform === "win32" && "needs a POSIX shell for the fake binaries" };

function withEnv(t, key, value) {
  const prev = process.env[key];
  process.env[key] = value;
  t.after(() => {
    if (prev === undefined) delete process.env[key];
    else process.env[key] = prev;
  });
}

test("runJadx: clean exit is not partial", posix, async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  withEnv(t, "JADX_PATH", fakeBin(path.join(dir, "jadx"), 'mkdir -p "$2/sources"; exit 0'));
  const result = await runJadx("x.apk", path.join(dir, "out"));
  assert.deepEqual(result, { partial: false });
});

test("runJadx: non-zero exit WITH output is a warning, not a failure", posix, async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  withEnv(t, "JADX_PATH", fakeBin(path.join(dir, "jadx"), 'mkdir -p "$2/sources"; echo x > "$2/sources/A.java"; exit 3'));
  const result = await runJadx("x.apk", path.join(dir, "out"));
  assert.equal(result.partial, true);
  assert.match(result.warning, /exit code 3/);
});

test("runJadx: non-zero exit with NO output still throws", posix, async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  withEnv(t, "JADX_PATH", fakeBin(path.join(dir, "jadx"), "exit 1"));
  await assert.rejects(runJadx("x.apk", path.join(dir, "out")), (err) => err.exitCode === 1);
});

test("runJadx: a missing binary throws", async (t) => {
  withEnv(t, "JADX_PATH", path.join(tmpdir(), "definitely-not-here"));
  await assert.rejects(runJadx("x.apk", path.join(tmpdir(), "out")));
});

test("runJadx: --deobf is passed only when asked", posix, async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const argsFile = path.join(dir, "args.txt");
  withEnv(t, "JADX_PATH", fakeBin(path.join(dir, "jadx"), `mkdir -p "$2/sources"; echo "$@" > "${argsFile}"`));
  const fs = require("fs");
  await runJadx("x.apk", path.join(dir, "o1"));
  assert.ok(!fs.readFileSync(argsFile, "utf8").includes("--deobf"));
  await runJadx("x.apk", path.join(dir, "o2"), { deobfuscate: true });
  assert.ok(fs.readFileSync(argsFile, "utf8").includes("--deobf"));
});
