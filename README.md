<p align="center">
  <img src="./assets/logo-wordmark.svg" alt="apk-unravel" width="480" />
</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/node-%3E%3D18-339933?logo=node.js&logoColor=white" alt="Node >=18">
  <img src="https://img.shields.io/badge/termux-ready-3DDC84?logo=android&logoColor=white" alt="Termux ready">
  <img src="https://img.shields.io/badge/CLI-commander-000000" alt="CLI: commander">
</p>

# apk-unravel

A CLI that wraps [`apktool`](https://apktool.org) and [`jadx`](https://github.com/skylot/jadx) into a single decompile pipeline, then parses the result into a readable summary: package info, permissions flagged by risk, exported components, and an optional heuristic scan for URLs/potential secrets across the decompiled source.

> "nothing is black box" 🙂

---

## What it does

`apk-unravel decompile app.apk` runs both tools back to back and gives you:

```
apk-unravel-out/app/
├── apktool/          # resources, AndroidManifest.xml, smali
├── jadx/              # readable Java source
├── report.json        # full structured analysis
└── report.md           # human-readable summary
```

**Where that lands, by default:**

- **Termux, with shared storage set up** (`termux-setup-storage` already run): `~/storage/shared/apk-unravel-out/<name>` — visible from your Android file manager under Internal Storage/apk-unravel-out, no root needed.
- **Termux, without shared storage set up:** falls back to `./apk-unravel-out/<name>` inside Termux's private storage, with a warning telling you to run `termux-setup-storage` for next time.
- **Everywhere else:** `./apk-unravel-out/<name>` relative to wherever you ran the command.

Override any of this with `-o <dir>`.

The report includes:

- App display name and icon (resolved from manifest `@string`/`@mipmap` refs and saved as a standalone `icon.png` next to the report)
- Package name, version, min/target SDK
- Every declared permission, flagged `dangerous` or `normal`
- Exported (or intent-filter-exposed) activities/services/receivers/providers — components reachable from outside the app
- Deep links / custom URI schemes declared via `<intent-filter><data>` tags, with whether each one is actually externally reachable
- Manifest-level security flags: `debuggable`, `allowBackup`, `usesCleartextTraffic`, referenced network security config
- Deep links / custom URI schemes reachable from outside the app, per component
- Native library (`lib/`) ABI coverage: which architectures ship, missing 64-bit support, legacy `armeabi` presence
- Optional (`--strings`): URLs and heuristically-flagged potential secrets found across the decompiled source (Java/Kotlin/smali/XML/JS/properties/etc.) — deduplicated across files, placeholder values filtered out, and values masked in the human-readable report (full values stay in `report.json`)
- Optional (`--grep <keywords>`): search the same decompiled source for your own comma-separated keywords or `/regex/flags` patterns — e.g. `--grep "firebase,MyCompanyName,/api\.internal\.[a-z]+/i"`. Works alongside or independently of `--strings`.
- Optional (`--strings-out <path>`): write string/keyword findings to a standalone `.json` or `.csv` file, separate from the full report — handy for spreadsheet review or diffing against a previous scan.

---

## Prerequisites

`apktool` and `jadx` are Java-based tools this CLI wraps — they are **not** npm packages and must be installed separately.

### Java (required by apktool)

```bash
# macOS
brew install openjdk

# Debian/Ubuntu
sudo apt install default-jre

# Termux
pkg install openjdk-17

# Or grab a JDK directly: https://adoptium.net
```

### apktool

```bash
# macOS
brew install apktool

# Debian/Ubuntu
sudo apt install apktool

# Termux
pkg install apktool

# Manual install (any OS): https://apktool.org/docs/install
```

### jadx

```bash
# macOS
brew install jadx

# Debian/Ubuntu / Termux
apt install jadx   # or: pkg install jadx

# Manual install (any OS, includes prebuilt binaries):
# https://github.com/skylot/jadx#downloads
```

**Alternatives if `pkg`/`apt` doesn't have it (or the packaged version misbehaves):** both tools also ship as portable downloads — apktool as a `.jar` ([releases](https://github.com/iBotPeaches/Apktool/releases)), jadx as a zip with a `bin/jadx` script inside ([releases](https://github.com/skylot/jadx/releases)). Neither needs compiling, just Java. Download, unzip if needed, then point `apk-unravel` at the file with `APKTOOL_PATH=/path/to/apktool.jar` and `JADX_PATH=/path/to/jadx/bin/jadx` (see below).

Once installed, verify everything is reachable:

```bash
apk-unravel doctor
```

If a tool isn't on your `PATH`, point to it explicitly instead of reinstalling:

```bash
export APKTOOL_PATH=/path/to/apktool      # or an apktool.jar path
export JADX_PATH=/path/to/jadx
export JAVA_PATH=/path/to/java
```

...or drop a `~/.apk-unravelrc.json`:

```json
{
  "apktoolPath": "/path/to/apktool",
  "jadxPath": "/path/to/jadx",
  "javaPath": "/path/to/java"
}
```

### Running on Termux

You'll also need Node.js itself, since `pkg`'s Java/apktool/jadx packages don't include it:

```bash
pkg install nodejs
```

APKs you want to analyze usually live in shared storage (e.g. your `Downloads` folder), not Termux's private home directory. Grant access once:

```bash
termux-setup-storage
```

Then reach shared storage via `~/storage/downloads/`, `~/storage/shared/`, etc.:

```bash
apk-unravel decompile ~/storage/downloads/app.apk
```

Everything else (`doctor`, `decompile`, env var overrides, `~/.apk-unravelrc.json`) works identically to any other Linux environment — Termux is just Linux under the hood.

---

## Install

```bash
npm install -g @boy-offi9-inc/apk-unravel
```

Or run locally without a global install:

```bash
git clone <this repo>
cd apk-unravel
npm install
npm link   # makes `apk-unravel` available globally, pointing at this checkout
```

---

## Usage

```bash
# Full pipeline: apktool + jadx + manifest report
apk-unravel decompile app.apk

# Custom output directory
apk-unravel decompile app.apk -o ./out/app

# Only resources/manifest (skip smali disassembly — faster)
apk-unravel decompile app.apk --no-smali

# Only run one tool
apk-unravel decompile app.apk --apktool-only
apk-unravel decompile app.apk --jadx-only

# Enable jadx's deobfuscation pass
apk-unravel decompile app.apk --deobfuscate

# Also scan decompiled source for URLs and potential secrets
apk-unravel decompile app.apk --strings

# Search decompiled source for custom keywords/regex alongside the built-in scan
apk-unravel decompile app.apk --strings --grep "firebase,MyCompanyName,/api\.internal\.[a-z]+/i"

# Export string/keyword findings to a separate file for spreadsheet review, diffing, etc.
apk-unravel decompile app.apk --strings --strings-out findings.csv

# Check your apktool/jadx/java installation
apk-unravel doctor
```

---

-feat: security analysis, app identity, and string scan improvements

- Fix exported-component detection to catch components with an
  intent-filter but no explicit android:exported attribute
- Add manifest-level security flags: debuggable, allowBackup,
  usesCleartextTraffic, network security config
- Resolve and export app label + icon (highest-density variant),
  copied into the report output
- Scan native library ABI coverage (lib/) — flags missing 64-bit
  support, legacy armeabi, single-ABI-only builds
- Expand string scan: more file types (kt/js/properties/etc.), more
  secret patterns (private keys, Slack, Stripe, JWT), dedup by value,
  placeholder filtering, masked values in report.md
- Add -g/--grep for custom keyword/regex search and --strings-out to
  export findings as standalone json/csv
  
---

## Notes

- **`Permission denied` running `apk-unravel`?** The bin script lost its executable bit somewhere along the way (common with zips/some Windows checkouts). Fix it with `chmod +x $(which apk-unravel)`. A `postinstall` script now sets this automatically on fresh `npm install`s.
- The `--strings` scan is a best-effort heuristic (regex-based), not a guarantee — always verify a flagged match before treating it as a real credential.
- "Exported" components are flagged based on an explicit `android:exported="true"` attribute *or* the presence of an `<intent-filter>` without an explicit `exported="false"` — a very common real-world misconfiguration worth a manual look.
- Only analyze APKs you own or have explicit permission to inspect.

## License

MIT
