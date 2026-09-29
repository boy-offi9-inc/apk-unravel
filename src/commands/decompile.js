const path = require("path");
const fs = require("fs-extra");
const ora = require("ora");
const logger = require("../lib/logger");
const { runApktool } = require("../lib/runners/apktool");
const { runJadx } = require("../lib/runners/jadx");
const { parseManifest } = require("../lib/manifest");
const { resolveAppIdentity } = require("../lib/appIdentity");
const { scanNativeLibs } = require("../lib/nativeLibs");
const { scanStrings, parseKeywords } = require("../lib/stringScan");
const { writeStringsExport } = require("../lib/stringsExport");
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
      const jadxResult = await runJadx(resolvedApk, jadxOut, { deobfuscate: options.deobfuscate });
      if (jadxResult.partial) {
        spinner.warn("jadx finished with errors — some classes could not be decompiled (output kept)");
        logger.dim(`  ${jadxResult.warning}`);
      } else {
        spinner.succeed("jadx decompile complete");
      }
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
  let appIdentity = null;
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

    if (manifest) {
      const identitySpinner = ora("Resolving app label and icon...").start();
      try {
        appIdentity = await resolveAppIdentity(apktoolOut, outRoot, manifest.appLabelRef, manifest.appIconRef);
        identitySpinner.succeed(
          appIdentity.iconOutputPath
            ? `App identity resolved — "${appIdentity.label || "—"}" (icon saved)`
            : `App identity resolved — "${appIdentity.label || "—"}" (no icon found)`
        );
      } catch (err) {
        identitySpinner.fail("Could not resolve app label/icon");
        logger.dim(err.message);
      }
    }
  }

  let stringScan = null;
  const { compiled: keywordMatchers, invalid: invalidKeywords } = parseKeywords(options.grep);
  for (const bad of invalidKeywords) {
    logger.warn(`Ignoring invalid --grep pattern "${bad.keyword}": ${bad.error}`);
  }

  if (options.strings || keywordMatchers.length) {
    const scanRoot = !skipJadx ? jadxOut : apktoolOut;
    const spinner = ora("Scanning decompiled source for URLs, potential secrets, and keywords...").start();
    try {
      stringScan = await scanStrings(scanRoot, { keywords: keywordMatchers });
      const parts = [`${stringScan.urls.length} URLs`, `${stringScan.potentialSecrets.length} unique secrets flagged`];
      if (keywordMatchers.length) parts.push(`${stringScan.keywordMatches.length} keyword matches`);
      spinner.succeed(`String scan complete — ${parts.join(", ")}`);
    } catch (err) {
      spinner.fail("String scan failed");
      logger.error(err.message);
    }

    if (stringScan && options.stringsOut) {
      try {
        const exportPath = path.isAbsolute(options.stringsOut) ? options.stringsOut : path.join(outRoot, options.stringsOut);
        await writeStringsExport(stringScan, exportPath);
        logger.dim(`String/keyword findings exported to ${exportPath}`);
      } catch (err) {
        logger.warn(`Could not write --strings-out file: ${err.message}`);
      }
    }
  }

  let nativeLibs = null;
  if (!skipApktool) {
    const spinner = ora("Scanning native libraries (lib/)...").start();
    try {
      nativeLibs = await scanNativeLibs(apktoolOut);
      spinner.succeed(
        nativeLibs.present
          ? `Native libs found — ${nativeLibs.abis.map((a) => a.abi).join(", ")}`
          : "No native libraries (lib/) present"
      );
    } catch (err) {
      spinner.fail("Native library scan failed");
      logger.dim(err.message);
    }
  }

  if (manifest) {
    const report = {
      apkFile: resolvedApk,
      generatedAt: new Date().toISOString(),
      manifest,
      appIdentity,
      stringScan,
      nativeLibs,
      outputPaths: {
        apktool: skipApktool ? null : apktoolOut,
        jadx: skipJadx ? null : jadxOut,
      },
    };

    const { jsonPath, mdPath } = await writeReport(report, outRoot);

    logger.section("Summary");
    logger.kv("App", appIdentity?.label || "—");
    logger.kv("Package", manifest.packageName || "—");
    logger.kv("Version", `${manifest.versionName || "—"} (${manifest.versionCode || "—"})`);
    logger.kv("SDK", `min ${manifest.minSdk || "—"} / target ${manifest.targetSdk || "—"}`);
    logger.kv("Permissions", `${manifest.permissions.length} total, ${manifest.dangerousPermissions.length} dangerous`);
    logger.kv("Exported/intent-filtered components", manifest.flaggedExported.length);
    logger.kv("Deep links / custom URI schemes", manifest.deepLinks.length);
    if (manifest.deepLinks.length) {
      for (const l of manifest.deepLinks) {
        const uri = `${l.scheme || "*"}://${l.host || "*"}${l.path || ""}`;
        logger.dim(`  ${l.reachable ? "⚠" : "·"} ${uri} → ${l.component}`);
      }
    }
    logger.kv("Security flags", manifest.security.flags.length);
    if (manifest.security.flags.length) {
      for (const f of manifest.security.flags) {
        logger.dim(`  ⚠ [${f.severity}] ${f.flag} — ${f.detail}`);
      }
    }
    if (stringScan) {
      logger.kv("URLs found", stringScan.urls.length);
      logger.kv("Potential secrets flagged (unique)", stringScan.potentialSecrets.length);
      if (keywordMatchers.length) {
        logger.kv("Keyword matches (unique)", stringScan.keywordMatches.length);
      }
    }
    if (nativeLibs?.present) {
      logger.kv("Native ABIs", nativeLibs.abis.map((a) => `${a.abi} (${a.libraryCount})`).join(", "));
      for (const f of nativeLibs.flags) {
        logger.dim(`  ⚠ [${f.severity}] ${f.flag} — ${f.detail}`);
      }
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
