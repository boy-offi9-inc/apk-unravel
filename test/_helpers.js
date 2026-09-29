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

module.exports = { tmpdir, rmrf, write, fakeBin, MANIFEST };
