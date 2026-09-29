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
 * opts.deobfuscate enables jadx's built-in deobfuscation pass.
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
  args.push(apkPath);

  try {
    await execa(jadx.command, args);
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
