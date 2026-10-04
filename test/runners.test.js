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

test("runJadx: extra args go between -d/--deobf and the APK path", posix, async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const argsFile = path.join(dir, "args.txt");
  withEnv(t, "JADX_PATH", fakeBin(path.join(dir, "jadx"), `mkdir -p "$2/sources"; printf '%s\\n' "$@" > "${argsFile}"`));
  const fs = require("fs");
  await runJadx("/in/app.apk", path.join(dir, "o"), { deobfuscate: true, extraArgs: ["--threads-count", "1", "--no-imports"] });
  assert.deepEqual(fs.readFileSync(argsFile, "utf8").trim().split("\n"), ["-d", path.join(dir, "o"), "--deobf", "--threads-count", "1", "--no-imports", "/in/app.apk"]);
});

test("runJadx: javaOpts become JAVA_OPTS for jadx and append to an existing JAVA_OPTS", posix, async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  const envFile = path.join(dir, "env.txt");
  withEnv(t, "JADX_PATH", fakeBin(path.join(dir, "jadx"), `mkdir -p "$2/sources"; printf '%s' "$JAVA_OPTS" > "${envFile}"`));
  const fs = require("fs");

  delete process.env.JAVA_OPTS;
  await runJadx("a.apk", path.join(dir, "o1"), { javaOpts: "-Xmx6g" });
  assert.equal(fs.readFileSync(envFile, "utf8"), "-Xmx6g");

  withEnv(t, "JAVA_OPTS", "-Dfile.encoding=UTF-8");
  await runJadx("a.apk", path.join(dir, "o2"), { javaOpts: "-Xmx6g" });
  assert.equal(fs.readFileSync(envFile, "utf8"), "-Dfile.encoding=UTF-8 -Xmx6g");

  await runJadx("a.apk", path.join(dir, "o3"));
  assert.equal(fs.readFileSync(envFile, "utf8"), "-Dfile.encoding=UTF-8", "without --jadx-java-opts the caller's JAVA_OPTS is inherited unchanged");
});
