const execa = require("execa");
const logger = require("../lib/logger");
const { resolveToolConfig } = require("../lib/toolConfig");
const { checkApktool } = require("../lib/runners/apktool");
const { checkJadx } = require("../lib/runners/jadx");

async function checkJava() {
  const { java } = resolveToolConfig();
  const { stderr, stdout } = await execa(java.command, ["-version"]);
  // `java -version` prints to stderr on most JDKs
  return (stderr || stdout).split("\n")[0].trim();
}

async function doctorCommand() {
  logger.title("apk-unravel doctor");
  logger.dim("Checking that required external tools are reachable...\n");

  const checks = [
    { name: "Java (required by apktool)", fn: checkJava, hint: "Install a JDK: https://adoptium.net" },
    { name: "apktool", fn: checkApktool, hint: "https://apktool.org/docs/install — or set APKTOOL_PATH" },
    { name: "jadx", fn: checkJadx, hint: "https://github.com/skylot/jadx#downloads — or set JADX_PATH" },
  ];

  let allOk = true;
  for (const check of checks) {
    try {
      const version = await check.fn();
      logger.success(`${check.name} — ${version}`);
    } catch (err) {
      allOk = false;
      logger.error(`${check.name} — not found or failed to run`);
      logger.dim(`  ↳ ${check.hint}`);
    }
  }

  console.log();
  if (allOk) {
    logger.success("All tools available. You're good to run `apk-unravel decompile <apk>`.");
  } else {
    logger.warn("Some tools are missing — install them (or point to them via env vars) before running `decompile`.");
    logger.dim("Env var overrides: APKTOOL_PATH, JADX_PATH, JAVA_PATH");
    logger.dim("Or create ~/.apk-unravelrc.json with { \"apktoolPath\": ..., \"jadxPath\": ..., \"javaPath\": ... }");
  }

  process.exitCode = allOk ? 0 : 1;
}

module.exports = doctorCommand;
