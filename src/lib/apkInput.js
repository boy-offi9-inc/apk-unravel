const path = require("path");
const fs = require("fs-extra");
const { hasZipMagic, readZipEntries, extractEntry, readEntryText } = require("./zip");

const BASE_NAMES = ["base.apk", "base-master.apk", "splits/base-master.apk"];
// config.arm64_v8a.apk, split_config.xxhdpi.apk, base-arm64_v8a.apk ... — resource/ABI splits, never the app's base.
const SPLIT_CONFIG = /(^|\/)(?:split_)?config\.[^/]+\.apk$|(^|\/)base-[^/]+\.apk$/i;

class InputError extends Error {}

function describeBytes(buf) {
  return Array.from(buf.subarray(0, 4)).map((b) => b.toString(16).padStart(2, "0")).join(" ") || "(empty)";
}

async function firstBytes(file) {
  const fsp = require("fs").promises;
  const fh = await fsp.open(file, "r");
  try {
    const b = Buffer.alloc(4);
    const { bytesRead } = await fh.read(b, 0, 4, 0);
    return b.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

async function pickBaseApk(file, apkEntries, allEntries) {
  const byLower = new Map(apkEntries.map((e) => [e.name.toLowerCase(), e]));

  for (const n of BASE_NAMES) if (byLower.has(n)) return byLower.get(n);

  // XAPK: manifest.json names the base split (or at least the package).
  const manifest = allEntries.find((e) => e.name === "manifest.json");
  if (manifest) {
    try {
      const json = JSON.parse(await readEntryText(file, manifest));
      const base = (json.split_apks || []).find((s) => s && s.id === "base" && s.file);
      if (base && byLower.has(String(base.file).toLowerCase())) return byLower.get(String(base.file).toLowerCase());
      if (json.package_name && byLower.has(`${json.package_name}.apk`.toLowerCase())) return byLower.get(`${json.package_name}.apk`.toLowerCase());
    } catch {
      // fall through to the size heuristic
    }
  }

  const nonConfig = apkEntries.filter((e) => !SPLIT_CONFIG.test(e.name));
  const pool = nonConfig.length ? nonConfig : apkEntries;
  return pool.slice().sort((a, b) => b.size - a.size)[0];
}

/**
 * Validates the input and, when it is a split-APK container (XAPK / APKS /
 * APKM), extracts its base APK so apktool/jadx — which only understand a
 * single APK — can run on it.
 *
 * @param {string} inputPath absolute path given by the user
 * @param {string} workDir   where an extracted base APK is written
 * @returns {Promise<{apkPath: string, kind: "apk"|"bundle", container?: string, baseEntry?: string, splitCount?: number, partial?: boolean, note?: string}>}
 * @throws {InputError} with a user-facing message
 */
async function prepareInput(inputPath, workDir) {
  if (!(await hasZipMagic(inputPath))) {
    const head = await firstBytes(inputPath);
    const hint = head.toString("latin1", 0, 3) === "dex" ? " It looks like a bare DEX file — open it directly with jadx." : "";
    throw new InputError(`${path.basename(inputPath)} is not an APK/ZIP (starts with bytes ${describeBytes(head)}).${hint}`);
  }

  let entries;
  try {
    entries = await readZipEntries(inputPath);
  } catch (err) {
    throw new InputError(`${path.basename(inputPath)} is not a readable ZIP/APK: ${err.message}`);
  }
  const names = new Set(entries.map((e) => e.name));

  if (names.has("AndroidManifest.xml")) return { apkPath: inputPath, kind: "apk" };

  if (names.has("BundleConfig.pb") || names.has("base/manifest/AndroidManifest.xml")) {
    throw new InputError(
      "This is an Android App Bundle (.aab), which apktool can't decode. Build a universal APK first, e.g.:\n" +
        "  bundletool build-apks --bundle=app.aab --output=app.apks --mode=universal\n" +
        "and pass the resulting .apks (apk-unravel extracts its universal APK) — or any installable .apk."
    );
  }

  const apkEntries = entries.filter((e) => /\.apk$/i.test(e.name));
  if (!apkEntries.length) {
    throw new InputError(`${path.basename(inputPath)} is a ZIP but contains neither AndroidManifest.xml (an APK) nor any .apk files (a split-APK bundle).`);
  }

  const universal = apkEntries.find((e) => /(^|\/)universal\.apk$/i.test(e.name));
  const base = universal || (await pickBaseApk(inputPath, apkEntries, entries));
  const splitCount = apkEntries.length - 1;

  await fs.ensureDir(workDir);
  const dest = path.join(workDir, path.basename(base.name).replace(/[^\w.\-]/g, "_"));
  try {
    await extractEntry(inputPath, base, dest);
  } catch (err) {
    throw new InputError(`Couldn't extract ${base.name} from ${path.basename(inputPath)}: ${err.message}`);
  }

  const ext = path.extname(inputPath).slice(1).toUpperCase() || "ZIP";
  return {
    apkPath: dest,
    kind: "bundle",
    container: ext,
    baseEntry: base.name,
    splitCount,
    partial: !(universal || splitCount === 0),
    note:
      universal || splitCount === 0
        ? `Extracted ${base.name} from the ${ext} container.`
        : `Analyzing ${base.name} from the ${ext} container; the other ${splitCount} split APK(s) were not analyzed, so native libraries and density-specific resources that live in config splits won't appear in this report.`,
  };
}

module.exports = { prepareInput, InputError };
