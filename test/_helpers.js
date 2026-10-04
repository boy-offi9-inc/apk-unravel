const fs = require("fs");
const os = require("os");
const path = require("path");

/** Fresh temp dir; caller cleans up via t.after(() => rmrf(dir)). */
function tmpdir(prefix = "apk-unravel-test-") {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function rmrf(p) {
  fs.rmSync(p, { recursive: true, force: true });
}

function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
  return file;
}

/** Executable POSIX shell script (used as a fake apktool/jadx binary). */
function fakeBin(file, body) {
  write(file, `#!/bin/sh\n${body}\n`);
  fs.chmodSync(file, 0o755);
  return file;
}

const zlib = require("zlib");
const { crc32Update } = require("../src/lib/zip");

/**
 * Builds a ZIP in memory. entries: [{ name, data, store?: boolean, badCrc?: boolean }].
 * Deflates by default; `store` writes uncompressed; `badCrc` corrupts the
 * recorded CRC so extraction must fail.
 */
function makeZip(entries) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, "utf8");
    const raw = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? "");
    const method = e.store ? 0 : 8;
    const body = method === 8 ? zlib.deflateRawSync(raw) : raw;
    const crc = e.badCrc ? 0xdeadbeef : crc32Update(0, raw);

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(body.length, 18);
    lh.writeUInt32LE(raw.length, 22);
    lh.writeUInt16LE(name.length, 26);
    locals.push(lh, name, body);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(body.length, 20);
    ch.writeUInt32LE(raw.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, name);
    offset += lh.length + name.length + body.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

/** A minimal but structurally valid APK (a ZIP with a manifest and a dex). */
function makeApk(extra = []) {
  return makeZip([{ name: "AndroidManifest.xml", data: "<manifest/>" }, { name: "classes.dex", data: Buffer.from("dex\n035\0") }, ...extra]);
}

const MANIFEST = `<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="42" android:versionName="1.2.3" package="com.acme.demo">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <application android:debuggable="true" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:usesCleartextTraffic="true">
        <activity android:exported="true" android:name="com.acme.demo.Main">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name="com.acme.demo.DeepActivity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:host="open" android:scheme="acme"/>
            </intent-filter>
        </activity>
        <activity android:exported="false" android:name="com.acme.demo.PrivateActivity">
            <intent-filter>
                <action android:name="com.acme.demo.INTERNAL"/>
                <data android:scheme="acme-private"/>
            </intent-filter>
        </activity>
        <service android:exported="false" android:name="com.acme.demo.Svc"/>
        <receiver android:exported="true" android:name="com.acme.demo.Boot"/>
    </application>
</manifest>
`;

module.exports = { tmpdir, rmrf, write, fakeBin, makeZip, makeApk, MANIFEST };
