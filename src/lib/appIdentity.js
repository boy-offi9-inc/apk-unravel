const fs = require("fs-extra");
const path = require("path");
const { XMLParser } = require("fast-xml-parser");

// Density folders in priority order (highest quality first) — when a
// resource exists in more than one density bucket we want the crispest icon
// we can find, not just whichever readdir happens to return first.
const DENSITY_PRIORITY = [
  "xxxhdpi",
  "xxhdpi",
  "xhdpi",
  "hdpi",
  "mdpi",
  "ldpi",
  "anydpi",
];

function densityRank(dirName) {
  const idx = DENSITY_PRIORITY.findIndex((d) => dirName.includes(d));
  return idx === -1 ? DENSITY_PRIORITY.length : idx;
}

/**
 * Resolves an "@string/app_name" style reference by scanning every
 * res/values (and values-<locale>) folder's strings.xml for a matching
 * <string name="...">value</string> entry. Falls back to null
 * if it can't find one (unusual, but locale-split manifests can do this).
 */
async function resolveStringRef(resDir, resourceName) {
  if (!(await fs.pathExists(resDir))) return null;
  const entries = await fs.readdir(resDir);
  const valuesDirs = entries.filter((e) => e === "values" || e.startsWith("values-"));
  // Prefer the base "values" (default locale) over locale-specific variants.
  valuesDirs.sort((a, b) => (a === "values" ? -1 : b === "values" ? 1 : 0));

  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "" });

  for (const dir of valuesDirs) {
    const stringsPath = path.join(resDir, dir, "strings.xml");
    if (!(await fs.pathExists(stringsPath))) continue;
    try {
      const xml = await fs.readFile(stringsPath, "utf8");
      const parsed = parser.parse(xml);
      const strings = parsed.resources?.string;
      if (!strings) continue;
      const list = Array.isArray(strings) ? strings : [strings];
      const match = list.find((s) => s.name === resourceName);
      if (match !== undefined) {
        // fast-xml-parser gives text content directly when there are no
        // attributes/children on the tag.
        return typeof match === "object" ? match["#text"] ?? null : String(match);
      }
    } catch {
      // Malformed strings.xml in some locale variant — skip and keep looking.
      continue;
    }
  }
  return null;
}

/**
 * Resolves a resource reference like "@mipmap/ic_launcher" or "@drawable/icon"
 * to an actual file on disk under res/, preferring the highest-density
 * variant available (icons are commonly duplicated per-density).
 */
async function resolveDrawableRef(resDir, resourceType, resourceName) {
  if (!(await fs.pathExists(resDir))) return null;
  const entries = await fs.readdir(resDir);
  const candidateDirs = entries
    .filter((e) => e === resourceType || e.startsWith(`${resourceType}-`))
    .sort((a, b) => densityRank(a) - densityRank(b));

  for (const dir of candidateDirs) {
    const dirPath = path.join(resDir, dir);
    let files;
    try {
      files = await fs.readdir(dirPath);
    } catch {
      continue;
    }
    const match = files.find((f) => path.basename(f, path.extname(f)) === resourceName);
    if (match) {
      return path.join(dirPath, match);
    }
  }
  return null;
}

/**
 * Resolves the app's display label and icon file from the raw manifest refs
 * captured by parseManifest(). Handles both literal values (rare) and
 * "@type/name" resource references (the common case), and copies the
 * resolved icon into the report output root as "icon.<ext>" so it's a real,
 * standalone artifact rather than just a path buried in apktool's res tree.
 *
 * @param {string} apktoolOutDir - apktool's decompile output dir
 * @param {string} outRoot - report output root (icon gets copied here)
 * @param {string} [appLabelRef] - raw android:label value from the manifest
 * @param {string} [appIconRef] - raw android:icon value from the manifest
 */
async function resolveAppIdentity(apktoolOutDir, outRoot, appLabelRef, appIconRef) {
  const resDir = path.join(apktoolOutDir, "res");
  let label = appLabelRef || null;
  let iconSourcePath = null;
  let iconOutputPath = null;

  if (appLabelRef && appLabelRef.startsWith("@string/")) {
    const resolved = await resolveStringRef(resDir, appLabelRef.replace("@string/", ""));
    label = resolved || appLabelRef; // fall back to the raw ref if lookup fails
  }

  if (appIconRef && appIconRef.startsWith("@")) {
    const [resourceType, resourceName] = appIconRef.slice(1).split("/");
    if (resourceType && resourceName) {
      iconSourcePath = await resolveDrawableRef(resDir, resourceType, resourceName);
    }
  }

  if (iconSourcePath) {
    const ext = path.extname(iconSourcePath) || ".png";
    const dest = path.join(outRoot, `icon${ext}`);
    try {
      await fs.copy(iconSourcePath, dest, { overwrite: true });
      iconOutputPath = dest;
    } catch {
      // Non-fatal — vector drawables (.xml) or unusual formats can fail to
      // copy meaningfully; the report just omits the icon path in that case.
      iconOutputPath = null;
    }
  }

  return { label, iconSourcePath, iconOutputPath };
}

module.exports = { resolveAppIdentity };
