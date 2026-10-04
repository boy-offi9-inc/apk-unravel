const path = require("path");
const fs = require("fs-extra");
const execa = require("execa");
const { resolveToolConfig } = require("../toolConfig");

/**
 * True if jadx left any usable output behind (decompiled sources or
 * decoded resources).
 */
async function hasOutput(outDir) {
  for (const sub of ["sources", "resources"]) {
    if (await fs.pathExists(path.join(outDir, sub))) return true;
  }
  return false;
}

/**
 * Runs jadx to decompile the APK's bytecode into readable Java source.
 * opts.deobfuscate enables jadx's built-in deobfuscation pass; opts.extraArgs
 * (array) is passed through to jadx before the APK path; opts.javaOpts sets
 * JAVA_OPTS for the jadx process.
 *
 * jadx exits non-zero whenever *some* classes fail to decompile, yet it still
 * writes everything it managed to recover. That's the normal case on real-world
 * (especially obfuscated) apps, so a non-zero exit with output on disk is
 * reported as `{ partial: true, warning }` instead of being thrown. A missing
 * binary, or a failure that produced no output at all, still throws.
 */
async function runJadx(apkPath, outDir, opts = {}) {
  const { jadx } = resolveToolConfig();

  const args = ["-d", outDir];
  if (opts.deobfuscate) args.push("--deobf");
  if (opts.extraArgs && opts.extraArgs.length) args.push(...opts.extraArgs);
  args.push(apkPath);

  // JVM options (e.g. "-Xmx6g" for big apps that hit OutOfMemoryError). jadx's
  // launcher appends JAVA_OPTS after its own defaults, so these win. Anything
  // already in the caller's JAVA_OPTS is kept.
  const execOpts = {};
  if (opts.javaOpts) {
    execOpts.env = { JAVA_OPTS: [process.env.JAVA_OPTS, opts.javaOpts].filter(Boolean).join(" ") };
  }

  try {
    await execa(jadx.command, args, execOpts);
    return { partial: false };
  } catch (err) {
    if (typeof err.exitCode === "number" && (await hasOutput(outDir))) {
      return { partial: true, warning: err.shortMessage || err.message };
    }
    throw err;
  }
}

async function checkJadx() {
  const { jadx } = resolveToolConfig();
  const { stdout } = await execa(jadx.command, ["--version"]);
  return stdout.trim();
}

module.exports = { runJadx, checkJadx };
