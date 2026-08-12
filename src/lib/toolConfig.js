/**
 * apk-unravel wraps two external, independently-installed tools:
 *   - apktool  https://apktool.org
 *   - jadx     https://github.com/skylot/jadx
 *
 * Neither ships as an npm package (they're Java-based), so this module
 * just resolves how to invoke them: PATH by default, or explicit
 * overrides via environment variables / a local config file.
 */
const path = require("path");
const fs = require("fs");
const os = require("os");

function readLocalConfig() {
  const configPath = path.join(os.homedir(), ".apk-unravelrc.json");
  if (fs.existsSync(configPath)) {
    try {
      return JSON.parse(fs.readFileSync(configPath, "utf8"));
    } catch {
      return {};
    }
  }
  return {};
}

function resolveToolConfig() {
  const local = readLocalConfig();

  return {
    apktool: {
      // If APKTOOL_PATH points at a .jar, we invoke it via `java -jar <path>`.
      // Otherwise treat it as an executable/script on PATH (e.g. the apktool wrapper script).
      command: process.env.APKTOOL_PATH || local.apktoolPath || "apktool",
      isJar: /\.jar$/i.test(process.env.APKTOOL_PATH || local.apktoolPath || ""),
    },
    jadx: {
      command: process.env.JADX_PATH || local.jadxPath || "jadx",
    },
    java: {
      command: process.env.JAVA_PATH || local.javaPath || "java",
    },
  };
}

module.exports = { resolveToolConfig, readLocalConfig };
