const execa = require("execa");
const { resolveToolConfig } = require("../toolConfig");

/**
 * Runs jadx to decompile the APK's bytecode into readable Java source.
 * opts.deobfuscate enables jadx's built-in deobfuscation pass.
 */
async function runJadx(apkPath, outDir, opts = {}) {
  const { jadx } = resolveToolConfig();

  const args = ["-d", outDir];
  if (opts.deobfuscate) args.push("--deobf");
  args.push(apkPath);

  return execa(jadx.command, args);
}

async function checkJadx() {
  const { jadx } = resolveToolConfig();
  const { stdout } = await execa(jadx.command, ["--version"]);
  return stdout.trim();
}

module.exports = { runJadx, checkJadx };
