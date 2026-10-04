const path = require("path");
const fs = require("fs-extra");
const { createSpinner } = require("../lib/output");
const logger = require("../lib/logger");
const { runApktool } = require("../lib/runners/apktool");
const { runJadx } = require("../lib/runners/jadx");
const { parseManifest } = require("../lib/manifest");
const { resolveAppIdentity } = require("../lib/appIdentity");
const { scanNativeLibs } = require("../lib/nativeLibs");
const { scanStrings, parseKeywords } = require("../lib/stringScan");
const { writeStringsExport } = require("../lib/stringsExport");
const { writeReport, toPublicReport } = require("../lib/report");
const { resolveDefaultOutputDir, isTermux } = require("../lib/outputPath");
const { prepareInput, InputError } = require("../lib/apkInput");
const { splitArgs } = require("../lib/shellSplit");
const { loadCustomRules, RuleError } = require("../lib/customRules");

// jadx flags that relocate or reshape its output; the report/scan stages rely
// on the default <out>/jadx/{sources,resources} layout.
const JADX_LAYOUT_FLAGS = new Set(["-d", "--output-dir", "-ds", "--output-dir-src", "-dr", "--output-dir-res", "-e", "--export-gradle"]);

function parseJadxArgs(raw) {
  if (!raw) return [];
  let args;
  try {
    args = splitArgs(raw);
  } catch (err) {
    throw new InputError(`Couldn't parse --jadx-args (${err.message}): ${raw}`);
  }
  const bad = args.find((a) => JADX_LAYOUT_FLAGS.has(a.split("=")[0]));
  if (bad) {
    throw new InputError(`--jadx-args can't include ${bad}: apk-unravel controls jadx's output layout so the report and scans can find the files.`);
  }
  return args;
}

async function decompileCommand(apkPath, options) {
  const quiet = Boolean(options.json || options.quiet);
  logger.setQuiet(quiet);
  const spin = (text) => createSpinner(text, { quiet });

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

  if (options.apktoolOnly && options.jadxOnly) {
    logger.error("--apktool-only and --jadx-only can't be combined — pick one (or neither to run both).");
    process.exitCode = 1;
    return;
  }

  let jadxExtraArgs;
  try {
    jadxExtraArgs = parseJadxArgs(options.jadxArgs);
  } catch (err) {
    if (!(err instanceof InputError)) throw err;
    logger.error(err.message);
    process.exitCode = 1;
    return;
  }

  // User-defined rules are parsed up front: a typo in a pattern should fail in
  // milliseconds, not after minutes of apktool/jadx.
  let customRules;
  try {
    customRules = await loadCustomRules(options);
  } catch (err) {
    if (!(err instanceof RuleError)) throw err;
    logger.error(err.message);
    process.exitCode = 1;
    return;
  }

  // Accept split-APK containers (.xapk/.apks/.apkm) by extracting their base
  // APK; reject non-APK input (AAB, truncated downloads, ...) with a clear reason.
  let toolApk = resolvedApk;
  let input = { kind: "apk" };
  try {
    input = await prepareInput(resolvedApk, path.join(outRoot, "input"));
    toolApk = input.apkPath;
  } catch (err) {
    if (!(err instanceof InputError)) throw err;
    logger.error(err.message);
    process.exitCode = 1;
    return;
  }
  if (input.note) (input.partial ? logger.warn : logger.info)(input.note);

  const skipApktool = options.jadxOnly;
  const skipJadx = options.apktoolOnly;

  // Manifest, resources (label/icon) and lib/ come from apktool when it ran.
  // With --jadx-only, jadx has already decoded the same things into
  // <jadxOut>/resources (AndroidManifest.xml, res/, lib/), so read them from
  // there and still produce a full report.
  const resourceRoot = skipApktool ? path.join(jadxOut, "resources") : apktoolOut;

  if (!skipApktool) {
    const spinner = spin("Running apktool (resources, manifest, smali)...").start();
    try {
      await runApktool(toolApk, apktoolOut, { noSrc: options.noSmali });
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
    const spinner = spin("Running jadx (Java source decompile)...").start();
    try {
      const jadxResult = await runJadx(toolApk, jadxOut, {
        deobfuscate: options.deobfuscate,
        extraArgs: jadxExtraArgs,
        javaOpts: options.jadxJavaOpts,
      });
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
  {
    const spinner = spin("Parsing AndroidManifest.xml...").start();
    try {
      manifest = await parseManifest(resourceRoot);
      spinner.succeed(
        `Manifest parsed — ${manifest.permissions.length} permissions, ${manifest.dangerousPermissions.length} flagged dangerous`
      );
    } catch (err) {
      spinner.fail("Manifest parsing failed");
      logger.error(err.message);
    }

    if (manifest) {
      const identitySpinner = spin("Resolving app label and icon...").start();
      try {
        appIdentity = await resolveAppIdentity(resourceRoot, outRoot, manifest.appLabelRef, manifest.appIconRef);
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

  // Rules from --grep-file / a rules file with kind "match" behave like --grep terms.
  for (const r of customRules.matchRules) keywordMatchers.push({ keyword: r.name, regex: r.regex });
  const builtinSecrets = options.builtinSecrets !== false;

  if (options.strings || keywordMatchers.length || customRules.secretRules.length) {
    if (!builtinSecrets && !customRules.secretRules.length) {
      logger.warn("--no-builtin-secrets given without any --rule/--rules-file: no secret detectors are active (URLs and keyword matches are still reported).");
    }
    const scanRoot = !skipJadx ? jadxOut : apktoolOut;
    const spinner = spin("Scanning decompiled source for URLs, potential secrets, and keywords...").start();
    try {
      stringScan = await scanStrings(scanRoot, {
        keywords: keywordMatchers,
        secretRules: customRules.secretRules,
        builtinSecrets,
        skipLibs: Boolean(options.skipLibs),
        excludePackages: options.excludePkg ? options.excludePkg.split(",") : [],
      });
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
  {
    const spinner = spin("Scanning native libraries (lib/)...").start();
    try {
      nativeLibs = await scanNativeLibs(resourceRoot);
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
      input:
        input.kind === "bundle"
          ? { kind: "bundle", container: input.container, baseEntry: input.baseEntry, splitCount: input.splitCount, analyzedApk: toolApk, partial: Boolean(input.partial) }
          : { kind: "apk" },
      generatedAt: new Date().toISOString(),
      manifest,
      appIdentity,
      stringScan,
      nativeLibs,
      manifestSource: skipApktool ? "jadx" : "apktool",
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
    logger.kv(
      "Exported/intent-filtered components",
      `${manifest.flaggedExported.length} (${manifest.unguardedExported.length} unguarded, excluding launcher)`
    );
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
    logger.blank();
    logger.success(`Full report written to:`);
    logger.dim(`  ${mdPath}`);
    logger.dim(`  ${jsonPath}`);
    if (usedSharedStorage) {
      logger.dim(`  (in shared storage — visible from your file manager under Internal Storage/apk-unravel-out)`);
    }

    if (options.json) {
      process.stdout.write(JSON.stringify(toPublicReport(report), null, 2) + "\n");
    } else if (quiet) {
      console.log(jsonPath);
    }
  } else {
    logger.warn("No manifest data available — skipped report generation (see the manifest parsing error above).");
    process.exitCode = 1;
  }
}

module.exports = decompileCommand;
