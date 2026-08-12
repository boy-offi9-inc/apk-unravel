const path = require("path");
const fs = require("fs-extra");
const ora = require("ora");
const logger = require("../lib/logger");
const { runApktool } = require("../lib/runners/apktool");
const { runJadx } = require("../lib/runners/jadx");
const { parseManifest } = require("../lib/manifest");
const { scanStrings } = require("../lib/stringScan");
const { writeReport } = require("../lib/report");
const { resolveDefaultOutputDir, isTermux } = require("../lib/outputPath");

async function decompileCommand(apkPath, options) {
  const resolvedApk = path.resolve(apkPath);

  if (!(await fs.pathExists(resolvedApk))) {
    logger.error(`APK not found: ${resolvedApk}`);
    if (/^storage\//.test(apkPath) || /^sdcard\//.test(apkPath)) {
      logger.dim(`Looks like a shared-storage path missing its prefix — did you mean:`);
      logger.dim(`  ~/${apkPath}   (Termux symlink, needs termux-setup-storage)`);
      logger.dim(`  /${apkPath.replace(/^sdcard\//, "storage/emulated/0/")}   (absolute path)`);
    }
    process.exitCode = 1;
    return;
  }

  const apkBaseName = path.basename(resolvedApk, path.extname(resolvedApk));

  let outRoot;
  let usedSharedStorage = false;
  if (options.output) {
    outRoot = path.resolve(options.output);
  } else {
    const defaultOut = await resolveDefaultOutputDir(apkBaseName);
    outRoot = defaultOut.dir;
    usedSharedStorage = defaultOut.accessible && isTermux();
    if (defaultOut.reason) {
      logger.warn(defaultOut.reason);
    }
  }

  const apktoolOut = path.join(outRoot, "apktool");
  const jadxOut = path.join(outRoot, "jadx");

  await fs.ensureDir(outRoot);

  logger.title(`apk-unravel — ${path.basename(resolvedApk)}`);
  logger.dim(`Output: ${outRoot}\n`);

  const skipApktool = options.jadxOnly;
  const skipJadx = options.apktoolOnly;

  if (!skipApktool) {
    const spinner = ora("Running apktool (resources, manifest, smali)...").start();
    try {
      await runApktool(resolvedApk, apktoolOut, { noSrc: options.noSmali });
      spinner.succeed("apktool decompile complete");
    } catch (err) {
      spinner.fail("apktool failed");
      logger.error(err.shortMessage || err.message);
      logger.dim("Run `apk-unravel doctor` to check your apktool installation.");
      process.exitCode = 1;
      return;
    }
  } else {
    logger.dim("Skipping apktool (--jadx-only)");
  }

  if (!skipJadx) {
    const spinner = ora("Running jadx (Java source decompile)...").start();
    try {
      await runJadx(resolvedApk, jadxOut, { deobfuscate: options.deobfuscate });
      spinner.succeed("jadx decompile complete");
    } catch (err) {
      spinner.fail("jadx failed");
      logger.error(err.shortMessage || err.message);
      logger.dim("Run `apk-unravel doctor` to check your jadx installation.");
      process.exitCode = 1;
      return;
    }
  } else {
    logger.dim("Skipping jadx (--apktool-only)");
  }

  let manifest = null;
  if (!skipApktool) {
    const spinner = ora("Parsing AndroidManifest.xml...").start();
    try {
      manifest = await parseManifest(apktoolOut);
      spinner.succeed(
        `Manifest parsed — ${manifest.permissions.length} permissions, ${manifest.dangerousPermissions.length} flagged dangerous`
      );
    } catch (err) {
      spinner.fail("Manifest parsing failed");
      logger.error(err.message);
    }
  }

  let stringScan = null;
  if (options.strings) {
    const scanRoot = !skipJadx ? jadxOut : apktoolOut;
    const spinner = ora("Scanning decompiled source for URLs and potential secrets...").start();
    try {
      stringScan = await scanStrings(scanRoot);
      spinner.succeed(
        `String scan complete — ${stringScan.urls.length} URLs, ${stringScan.potentialSecrets.length} flagged strings`
      );
    } catch (err) {
      spinner.fail("String scan failed");
      logger.error(err.message);
    }
  }

  if (manifest) {
    const report = {
      apkFile: resolvedApk,
      generatedAt: new Date().toISOString(),
      manifest,
      stringScan,
      outputPaths: {
        apktool: skipApktool ? null : apktoolOut,
        jadx: skipJadx ? null : jadxOut,
      },
    };

    const { jsonPath, mdPath } = await writeReport(report, outRoot);

    logger.section("Summary");
    logger.kv("Package", manifest.packageName || "—");
    logger.kv("Version", `${manifest.versionName || "—"} (${manifest.versionCode || "—"})`);
    logger.kv("SDK", `min ${manifest.minSdk || "—"} / target ${manifest.targetSdk || "—"}`);
    logger.kv("Permissions", `${manifest.permissions.length} total, ${manifest.dangerousPermissions.length} dangerous`);
    logger.kv("Exported/intent-filtered components", manifest.flaggedExported.length);
    if (stringScan) {
      logger.kv("URLs found", stringScan.urls.length);
      logger.kv("Potential secrets flagged", stringScan.potentialSecrets.length);
    }
    console.log();
    logger.success(`Full report written to:`);
    logger.dim(`  ${mdPath}`);
    logger.dim(`  ${jsonPath}`);
    if (usedSharedStorage) {
      logger.dim(`  (in shared storage — visible from your file manager under Internal Storage/apk-unravel-out)`);
    }
  } else {
    logger.warn("No manifest data available — skipped report generation (apktool step was skipped or failed).");
  }
}

module.exports = decompileCommand;
