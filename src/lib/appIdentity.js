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

const RASTER_EXTS = new Set([".png", ".webp", ".jpg", ".jpeg"]);
const MAX_ICON_REF_DEPTH = 3;

/**
 * Lists every res/<type>[-qualifier]/<name>.* file, best density first.
 */
async function findResourceFiles(resDir, resourceType, resourceName) {
  if (!(await fs.pathExists(resDir))) return [];
  const entries = await fs.readdir(resDir);
  const candidateDirs = entries
    .filter((e) => e === resourceType || e.startsWith(`${resourceType}-`))
    .sort((a, b) => densityRank(a) - densityRank(b));

  const found = [];
  for (const dir of candidateDirs) {
    const dirPath = path.join(resDir, dir);
    let files;
    try {
      files = await fs.readdir(dirPath);
    } catch {
      continue;
    }
    for (const f of files) {
      if (path.basename(f, path.extname(f)) === resourceName) {
        found.push({ path: path.join(dirPath, f), ext: path.extname(f).toLowerCase() });
      }
    }
  }
  return found;
}

/**
 * Adaptive icons (<adaptive-icon> XML) have no bitmap of their own — the
 * pixels live in the drawable their <foreground> points at. Returns that
 * "@type/name" reference, or null if the XML isn't an adaptive icon.
 */
async function adaptiveForegroundRef(xmlPath) {
  try {
    const parsed = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "" }).parse(await fs.readFile(xmlPath, "utf8"));
    const fg = parsed["adaptive-icon"]?.foreground;
    if (!fg || typeof fg !== "object") return null;
    return fg["android:drawable"] || fg.inset?.["android:drawable"] || null;
  } catch {
    return null;
  }
}

/**
 * Resolves a resource reference like "@mipmap/ic_launcher" or "@drawable/icon"
 * to a file under res/. Raster images (png/webp/jpg) always win over XML, and
 * among rasters the highest-density variant wins. If only XML exists and it's
 * an adaptive icon, follows its <foreground> to a raster (a few levels deep).
 *
 * Returns { path, kind: "raster" | "xml" } — "xml" means nothing bitmap-like
 * could be found, so the caller shouldn't treat `path` as a copyable icon —
 * or null if the resource doesn't exist at all.
 */
async function resolveDrawableRef(resDir, resourceType, resourceName, depth = 0) {
  const files = await findResourceFiles(resDir, resourceType, resourceName);

  const raster = files.find((f) => RASTER_EXTS.has(f.ext));
  if (raster) return { path: raster.path, kind: "raster" };

  const xml = files.find((f) => f.ext === ".xml");
  if (!xml) return null;

  if (depth < MAX_ICON_REF_DEPTH) {
    const fgRef = await adaptiveForegroundRef(xml.path);
    const m = fgRef && /^@(\w+)\/(.+)$/.exec(fgRef);
    if (m) {
      const viaForeground = await resolveDrawableRef(resDir, m[1], m[2], depth + 1);
      if (viaForeground && viaForeground.kind === "raster") return viaForeground;
    }
  }
  return { path: xml.path, kind: "xml" };
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
  let iconIsRaster = false;

  if (appLabelRef && appLabelRef.startsWith("@string/")) {
    const resolved = await resolveStringRef(resDir, appLabelRef.replace("@string/", ""));
    label = resolved || appLabelRef; // fall back to the raw ref if lookup fails
  }

  if (appIconRef && appIconRef.startsWith("@")) {
    const [resourceType, resourceName] = appIconRef.slice(1).split("/");
    if (resourceType && resourceName) {
      const resolved = await resolveDrawableRef(resDir, resourceType, resourceName);
      if (resolved) {
        iconSourcePath = resolved.path;
        // Only bitmaps are copied out as icon.<ext>; a bare XML vector/adaptive
        // icon with no raster behind it isn't viewable as an image, so we
        // report where it lives (iconSourcePath) but don't fake an icon file.
        iconIsRaster = resolved.kind === "raster";
      }
    }
  }

  if (iconSourcePath && iconIsRaster) {
    const ext = path.extname(iconSourcePath) || ".png";
    const dest = path.join(outRoot, `icon${ext}`);
    try {
      await fs.copy(iconSourcePath, dest, { overwrite: true });
      iconOutputPath = dest;
    } catch {
      // Non-fatal — the report just omits the icon path in that case.
      iconOutputPath = null;
    }
  }

  return { label, iconSourcePath, iconOutputPath };
}

module.exports = { resolveAppIdentity, resolveDrawableRef };
