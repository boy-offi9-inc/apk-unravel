<p align="center">
  <img src="./assets/logo-wordmark.svg" alt="apk-unravel" width="480" />
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

- Package name, version, min/target SDK
- Every declared permission, flagged `dangerous` or `normal`
- Exported (or intent-filter-exposed) activities/services/receivers/providers — components reachable from outside the app
- Optional (`--strings`): URLs and heuristically-flagged potential secrets found across the decompiled source

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

# Check your apktool/jadx/java installation
apk-unravel doctor
```

---

## Project structure

```
apk-unravel/
├── bin/
│   └── apk-unravel.js       # CLI entry point
├── src/
│   ├── commands/
│   │   ├── decompile.js      # main pipeline: apktool → jadx → parse → report
│   │   └── doctor.js         # verifies apktool/jadx/java are reachable
│   ├── lib/
│   │   ├── runners/
│   │   │   ├── apktool.js
│   │   │   └── jadx.js
│   │   ├── manifest.js       # parses apktool's decompiled AndroidManifest.xml
│   │   ├── permissions.js    # dangerous-permission reference list
│   │   ├── stringScan.js     # heuristic URL/secret scan across decompiled output
│   │   ├── report.js         # builds report.json + report.md
│   │   ├── toolConfig.js     # resolves apktool/jadx/java paths
│   │   └── logger.js
│   └── index.js               # commander CLI wiring
├── .github/workflows/ci.yml
├── LICENSE
└── package.json
```

---

## Notes

- **`Permission denied` running `apk-unravel`?** The bin script lost its executable bit somewhere along the way (common with zips/some Windows checkouts). Fix it with `chmod +x $(which apk-unravel)`. A `postinstall` script now sets this automatically on fresh `npm install`s.
- The `--strings` scan is a best-effort heuristic (regex-based), not a guarantee — always verify a flagged match before treating it as a real credential.
- "Exported" components are flagged based on an explicit `android:exported="true"` attribute *or* the presence of an `<intent-filter>` without an explicit `exported="false"` — a very common real-world misconfiguration worth a manual look.
- Only analyze APKs you own or have explicit permission to inspect.

## License

MIT
