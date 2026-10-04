const fs = require("fs-extra");
const path = require("path");
const { readElfLoadAlignment } = require("./elf");

// The set of ABIs Android actually recognizes. Anything else showing up as a
// lib/<dir> folder name is either a typo/bad build or something non-standard
// worth a second look.
const KNOWN_ABIS = new Set(["armeabi", "armeabi-v7a", "arm64-v8a", "x86", "x86_64"]);
const ABI_64_BIT = new Set(["arm64-v8a", "x86_64"]);
// armeabi (no revision) was deprecated in the Android NDK long ago — its
// continued presence usually means a very old toolchain/dependency.
const LEGACY_ABIS = new Set(["armeabi"]);

/**
 * Scans the decoded lib/ directory (a verbatim copy of the APK's
 * native library folder) and reports which ABIs are present, which .so files
 * ship under each, and a few common misconfiguration flags: no 64-bit ABI
 * at all (Play Store has required 64-bit support since 2019), legacy
 * `armeabi` presence, and single-ABI-only builds (not necessarily wrong —
 * app bundles commonly split by ABI at install time — but worth surfacing
 * since a *monolithic* single-ABI APK is unusual).
 *
 * @param {string} apktoolOutDir - apktool's decompile output dir
 */
async function scanNativeLibs(apktoolOutDir) {
  const libDir = path.join(apktoolOutDir, "lib");

  if (!(await fs.pathExists(libDir))) {
    return { present: false, abis: [], flags: [] };
  }

  const abiDirs = (await fs.readdir(libDir)).filter((name) => !name.startsWith("."));

  const abis = [];
  for (const abiName of abiDirs) {
    const abiPath = path.join(libDir, abiName);
    let stat;
    try {
      stat = await fs.stat(abiPath);
    } catch {
      continue;
    }
    if (!stat.isDirectory()) continue;

    let files = [];
    try {
      files = (await fs.readdir(abiPath)).filter((f) => f.endsWith(".so"));
    } catch {
      files = [];
    }

    files.sort();

    // 16 KB page-size compatibility only matters for the 64-bit ABIs, but the
    // alignment is cheap to read, so record it for every library.
    const alignment = {};
    for (const f of files) {
      const elf = await readElfLoadAlignment(path.join(abiPath, f));
      alignment[f] = elf.valid
        ? { aligned16k: elf.aligned16k, maxLoadAlign: Math.max(...elf.loadAlignments), minLoadAlign: Math.min(...elf.loadAlignments) }
        : { aligned16k: null, error: elf.error };
    }

    abis.push({
      abi: abiName,
      recognized: KNOWN_ABIS.has(abiName),
      is64Bit: ABI_64_BIT.has(abiName),
      legacy: LEGACY_ABIS.has(abiName),
      libraryCount: files.length,
      libraries: files,
      alignment,
      unaligned16k: files.filter((f) => alignment[f].aligned16k === false),
      unreadable: files.filter((f) => alignment[f].aligned16k === null),
    });
  }

  abis.sort((a, b) => a.abi.localeCompare(b.abi));

  const flags = [];
  const recognizedAbis = abis.filter((a) => a.recognized);

  if (recognizedAbis.length > 0 && !recognizedAbis.some((a) => a.is64Bit)) {
    flags.push({
      flag: "no64BitAbi",
      severity: "medium",
      detail: "No 64-bit ABI (arm64-v8a/x86_64) shipped — Google Play has required 64-bit support since August 2019; this build would be rejected or is a partial ABI split.",
    });
  }

  for (const a of abis.filter((x) => x.is64Bit && x.unaligned16k.length)) {
    const shown = a.unaligned16k.slice(0, 10).join(", ") + (a.unaligned16k.length > 10 ? `, … (+${a.unaligned16k.length - 10} more)` : "");
    flags.push({
      flag: "unaligned16kPageSize",
      severity: "medium",
      detail:
        `${a.unaligned16k.length} of ${a.libraryCount} ${a.abi} librar${a.unaligned16k.length === 1 ? "y has" : "ies have"} ELF LOAD segments aligned below 16 KB (${shown}). ` +
        "Google Play requires apps targeting Android 15+ to support 16 KB page sizes; rebuild with NDK r28+ or link with -Wl,-z,max-page-size=16384. " +
        "(Only ELF segment alignment is checked here — uncompressed .so files must also be 16 KB zip-aligned inside the APK, which apktool's output can't show.)",
    });
  }

  const legacyPresent = abis.filter((a) => a.legacy);
  for (const a of legacyPresent) {
    flags.push({
      flag: "legacyAbi",
      severity: "low",
      detail: `Legacy ABI "${a.abi}" present — deprecated by the NDK for years; usually indicates an old prebuilt dependency was bundled in.`,
    });
  }

  if (recognizedAbis.length === 1) {
    flags.push({
      flag: "singleAbiOnly",
      severity: "info",
      detail: `Only one ABI (${recognizedAbis[0].abi}) present. This is normal for an ABI-split bundle artifact, but unusual for a monolithic release APK.`,
    });
  }

  return {
    present: abis.length > 0,
    abis,
    flags,
  };
}

module.exports = { scanNativeLibs };
