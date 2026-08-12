const execa = require("execa");
const { resolveToolConfig } = require("../toolConfig");

/**
 * Runs `apktool d` to decompile resources, AndroidManifest.xml, and smali.
 * opts.noSrc skips smali disassembly and only pulls resources.
 */
async function runApktool(apkPath, outDir, opts = {}) {
  const { apktool, java } = resolveToolConfig();

  const args = ["d", "-f", "-o", outDir];
  if (opts.noSrc) args.push("-s");
  args.push(apkPath);

  if (apktool.isJar) {
    return execa(java.command, ["-jar", apktool.command, ...args]);
  }
  return execa(apktool.command, args);
}

async function checkApktool() {
  const { apktool, java } = resolveToolConfig();
  const args = apktool.isJar ? ["-jar", apktool.command, "-version"] : ["-version"];
  const bin = apktool.isJar ? java.command : apktool.command;
  const { stdout } = await execa(bin, args);
  return stdout.trim();
}

module.exports = { runApktool, checkApktool };
