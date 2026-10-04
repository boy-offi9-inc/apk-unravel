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

**Accepted input:** an `.apk`, or a split-APK container (`.xapk`, `.apks`, `.apkm`) — for those, the base APK is extracted into `<out>/input/` and analysed (a universal APK if the bundle has one). Anything else (an `.aab`, a truncated download, an HTML error page saved as `.apk`) is rejected with a specific message instead of a Java stack trace.

The report includes:

- App display name and icon (resolved from manifest `@string`/`@mipmap` refs and saved as a standalone `icon.png` next to the report)
- Package name, version, min/target SDK
- Every declared permission, tiered as **runtime** (user prompt), **special access** (overlay, all-files, install packages, usage stats, ...) or normal — including the Android 12–14 additions (`POST_NOTIFICATIONS`, `READ_MEDIA_*`, `BLUETOOTH_*`, `NEARBY_WIFI_DEVICES`, ...)
- Exported (or intent-filter-exposed) activities, activity-aliases, services, receivers and providers — with how each is exposed, which permission (if any) guards it, whether that guard is meaningless (a custom permission declared with `protectionLevel="normal"`), and the launcher entry point marked as expected. The headline count is the number of *unguarded* ones
- Deep links / custom URI schemes declared via `<intent-filter><data>` tags, with whether each one is actually externally reachable
- Manifest-level security flags: `debuggable`, `allowBackup`, `usesCleartextTraffic`, `testOnly`, `sharedUserId`, plus the parsed network security config (base/per-domain cleartext, user-CA trust outside `debug-overrides`, pinning)
- Native library (`lib/`) ABI coverage: which architectures ship, missing 64-bit support, legacy `armeabi` presence, and whether each 64-bit `.so` is **16 KB page-size compatible** (read straight from the ELF program headers — no extra tools)
- Optional (`--strings`): URLs and heuristically-flagged potential secrets found across the decompiled source (Java/Kotlin/smali/XML/JS/properties/etc.) — deduplicated across files, placeholder values filtered out, and values masked in the human-readable report (full values stay in `report.json`). Covers AWS/Google/Stripe/Slack/GitHub/SendGrid/Twilio/Mailgun/Telegram/Azure/JWT/private-key shapes; generic `api_key = "..."` hits must also look random (entropy check). URLs are summarised by domain, with cleartext `http://`, raw-IP and Firebase/S3/GCS/Azure-blob endpoints called out, and any URL that embeds a secret is masked
- Optional (`--grep <keywords>`): search the same decompiled source for your own comma-separated keywords or `/regex/flags` patterns — e.g. `--grep "firebase,MyCompanyName,/api\.internal\.[a-z]+/i"`. Works alongside or independently of `--strings`.
- Optional, **your own detectors** (`--rule`, `--rules-file`, `--grep-file`, `--no-builtin-secrets`): hunt for company-specific tokens, internal hostnames or any string you care about instead of relying only on the built-in patterns. Custom *secret* rules are reported masked, exactly like built-in secrets; custom *match* rules are listed verbatim. Rules are validated before any decompiling starts, so a typo fails instantly
- Optional (`--skip-libs`, `--exclude-pkg <packages>`): leave well-known third-party code (androidx, kotlin, gms, okhttp, ...) and any packages you name out of the string scan; the report says what was skipped
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
git clone https://github.com/boy-offi9-inc/apk-unravel.git
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

# Split-APK bundles work too (the base APK is analysed; other splits are not)
apk-unravel decompile app.xapk

# Look for your own secret format (value is masked in the report); implies a scan
apk-unravel decompile app.apk --rule 'internal=/ACME-[A-Z0-9]{8}/'

# Several rules, plus a keyword list, and ONLY your rules (no built-in patterns)
apk-unravel decompile app.apk --rule 'vault=/hvs\.[A-Za-z0-9_-]{20,}/' --grep-file hosts.txt --no-builtin-secrets

# A reusable rule set
apk-unravel decompile app.apk --rules-file my-rules.json

# Cut third-party noise out of the string scan
apk-unravel decompile app.apk --strings --skip-libs --exclude-pkg com.vendor.sdk

# Big app, jadx runs out of memory: more heap, fewer threads
apk-unravel decompile app.apk --jadx-java-opts "-Xmx6g" --jadx-args "--threads-count 1"

# Machine-readable: no banner/spinners, report JSON on stdout (secret values stay masked)
apk-unravel decompile app.apk --json --strings | jq '.manifest.security.flags'

# Quiet: print only the path to report.json (handy in scripts)
REPORT=$(apk-unravel decompile app.apk --quiet)

# Check your apktool/jadx/java installation
apk-unravel doctor
```

With `--json` / `--quiet`, warnings and errors still go to **stderr** and the exit code still reflects failure, so `apk-unravel ... --json > report.json` never mixes diagnostics into the data.

---

## Custom rules

`--rule "name=pattern"` (repeatable) adds a secret detector. The pattern is either a `/regex/flags` literal or plain text (matched literally, case-insensitive); the `name=` prefix is optional and becomes the label `Custom: name` in the report. A rule can't match the empty string.

`--rules-file` takes a `.txt` file (one `name=pattern` per line, `#` comments allowed) or a `.json` file for more control:

```json
{
  "rules": [
    { "name": "vault token", "regex": "hvs\\.[A-Za-z0-9_-]{20,}", "minEntropy": 3.5 },
    { "name": "case-insensitive", "regex": "internal-[a-z0-9]{10}", "flags": "i" },
    { "name": "staging host", "keyword": "staging.acme.example", "kind": "match" }
  ]
}
```

- `regex` (source, no slashes) **or** `keyword` (literal) — exactly one
- `flags` — any of `g i m s u` (`g` is always on)
- `kind` — `"secret"` (default; masked in output) or `"match"` (listed verbatim, like `--grep`)
- `minEntropy` — drop hits below this many bits/character (0–8); useful for tokens that otherwise collide with readable constants

`--grep-file words.txt` is `--grep` for long lists: one keyword or `/regex/` per line, so commas inside a regex are safe.

Custom rules are never run through the built-in placeholder filter — if you search for a string containing "example", you get it. URLs that contain a custom-secret hit are masked in the URL list too. A badly written regex (nested quantifiers) can be slow on large trees; the scan skips files over 4 MB but doesn't time-limit individual patterns.

## Notes

- **`Permission denied` running `apk-unravel`?** The bin script lost its executable bit somewhere along the way (common with zips/some Windows checkouts). Fix it with `chmod +x $(which apk-unravel)`. A `postinstall` script now sets this automatically on fresh `npm install`s.
- The `--strings` scan is a best-effort heuristic (regex-based), not a guarantee — always verify a flagged match before treating it as a real credential.
- **16 KB page size:** the check reads ELF `PT_LOAD` alignment of 64-bit libraries. Uncompressed `.so` files must *also* be 16 KB zip-aligned inside the APK; that can't be seen in decompiled output, so verify it with the Android SDK's `zipalign -c -P 16 -v 4 app.apk` (build-tools 35+).
- **Split-APK bundles:** only the base APK is analysed. Native libraries and density-specific resources that live in `config.*` splits won't appear in the report (a warning says so); pass a universal APK for a complete picture.
- **`--jadx-args`** is split like a shell would, but never run through one. Flags that change jadx's output layout (`-d`, `-ds`, `-dr`, `-e`) are rejected.
- "Exported" components are flagged based on an explicit `android:exported="true"` attribute *or* the presence of an `<intent-filter>` without an explicit `exported="false"` — a very common real-world misconfiguration worth a manual look.
- Only analyze APKs you own or have explicit permission to inspect.

- **`--jadx-only`** builds the same report as a full run: the manifest, app label/icon and native-lib scan are read from jadx's own decoded output (`jadx/resources/`) when apktool is skipped.
- **jadx exits non-zero on partial failures.** If some classes can't be decompiled but jadx still wrote output, apk-unravel prints a warning and carries on instead of aborting. A run that produced nothing still fails.
- Set `APK_UNRAVEL_DEBUG=1` to print a stack trace for unexpected errors.

## Development

```bash
npm install
npm test        # node:test suite; no extra dev dependencies
```

The end-to-end tests run the real CLI against small fake `apktool`/`jadx` scripts, so they need neither Java nor the real tools (POSIX shell required).

## License

MIT
