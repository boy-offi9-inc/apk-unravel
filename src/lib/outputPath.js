const os = require("os");
const path = require("path");
const fs = require("fs-extra");
const { isTermux } = require("./environment");

/**
 * Picks a default output directory for a given APK's analysis results.
 *
 * On Termux, results written under the app's private home directory
 * (/data/data/com.termux/files/home/...) aren't reachable from a regular
 * Android file manager without root. If shared storage access has been
 * granted (termux-setup-storage), we default there instead so reports are
 * actually easy to find and open/share afterward.
 *
 * Everywhere else (or if storage access hasn't been granted yet), we fall
 * back to the previous behavior: a folder relative to the current directory.
 */
async function resolveDefaultOutputDir(apkBaseName) {
  const fallback = path.resolve(`./apk-unravel-out/${apkBaseName}`);

  if (!isTermux()) {
    return { dir: fallback, accessible: true, reason: null };
  }

  const sharedStorage = path.join(os.homedir(), "storage", "shared");
  const hasSharedStorage = await fs.pathExists(sharedStorage);

  if (hasSharedStorage) {
    return {
      dir: path.join(sharedStorage, "apk-unravel-out", apkBaseName),
      accessible: true,
      reason: null,
    };
  }

  return {
    dir: fallback,
    accessible: false,
    reason:
      "Shared storage isn't set up yet, so results are staying inside Termux's private storage. Run `termux-setup-storage` once, then re-run this to have results land somewhere your file manager can reach.",
  };
}

module.exports = { resolveDefaultOutputDir, isTermux };
