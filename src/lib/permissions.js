/**
 * Android permission risk tiers used by the report.
 *
 * - RUNTIME_PERMISSIONS: "dangerous" protection level — the user is prompted at
 *   runtime (calendar, camera, contacts, location, mic, phone, sensors, SMS,
 *   storage/media, notifications, nearby devices, ...).
 * - SPECIAL_ACCESS_PERMISSIONS: not runtime prompts, but powerful enough to be
 *   worth flagging — the user grants them from a dedicated Settings screen (or
 *   Play policy gates them): overlay windows, all-files access, package
 *   installs, usage stats, exact alarms, and similar.
 *
 * `dangerous` on a parsed permission means "runtime OR special access", which
 * is what the summary counts have always meant; `tier` says which one.
 *
 * Reference: https://developer.android.com/reference/android/Manifest.permission
 */
const RUNTIME_PERMISSIONS = new Set([
  // Calendar / contacts / accounts
  "android.permission.READ_CALENDAR",
  "android.permission.WRITE_CALENDAR",
  "android.permission.READ_CONTACTS",
  "android.permission.WRITE_CONTACTS",
  "android.permission.GET_ACCOUNTS",
  // Camera / microphone
  "android.permission.CAMERA",
  "android.permission.RECORD_AUDIO",
  // Location
  "android.permission.ACCESS_FINE_LOCATION",
  "android.permission.ACCESS_COARSE_LOCATION",
  "android.permission.ACCESS_BACKGROUND_LOCATION",
  "android.permission.ACCESS_MEDIA_LOCATION",
  // Phone / calls
  "android.permission.READ_PHONE_STATE",
  "android.permission.READ_PHONE_NUMBERS",
  "android.permission.CALL_PHONE",
  "android.permission.ANSWER_PHONE_CALLS",
  "android.permission.READ_CALL_LOG",
  "android.permission.WRITE_CALL_LOG",
  "android.permission.ADD_VOICEMAIL",
  "android.permission.USE_SIP",
  "android.permission.PROCESS_OUTGOING_CALLS",
  // Sensors / activity
  "android.permission.BODY_SENSORS",
  "android.permission.BODY_SENSORS_BACKGROUND",
  "android.permission.ACTIVITY_RECOGNITION",
  "android.permission.UWB_RANGING",
  // SMS / MMS
  "android.permission.SEND_SMS",
  "android.permission.RECEIVE_SMS",
  "android.permission.READ_SMS",
  "android.permission.RECEIVE_WAP_PUSH",
  "android.permission.RECEIVE_MMS",
  // Storage / media (legacy + Android 13/14 granular media)
  "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE",
  "android.permission.READ_MEDIA_IMAGES",
  "android.permission.READ_MEDIA_VIDEO",
  "android.permission.READ_MEDIA_AUDIO",
  "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
  // Notifications / nearby devices (Android 12/13)
  "android.permission.POST_NOTIFICATIONS",
  "android.permission.BLUETOOTH_CONNECT",
  "android.permission.BLUETOOTH_SCAN",
  "android.permission.BLUETOOTH_ADVERTISE",
  "android.permission.NEARBY_WIFI_DEVICES",
]);

const SPECIAL_ACCESS_PERMISSIONS = new Set([
  "android.permission.MANAGE_EXTERNAL_STORAGE",
  "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.REQUEST_INSTALL_PACKAGES",
  "android.permission.REQUEST_DELETE_PACKAGES",
  "android.permission.QUERY_ALL_PACKAGES",
  "android.permission.PACKAGE_USAGE_STATS",
  "android.permission.WRITE_SETTINGS",
  "android.permission.SCHEDULE_EXACT_ALARM",
  "android.permission.USE_FULL_SCREEN_INTENT",
  "android.permission.ACCESS_NOTIFICATION_POLICY",
  "android.permission.MANAGE_MEDIA",
  "android.permission.MANAGE_OWN_CALLS",
]);

// Everything flagged as worth a look (kept for backward compatibility).
const DANGEROUS_PERMISSIONS = new Set([...RUNTIME_PERMISSIONS, ...SPECIAL_ACCESS_PERMISSIONS]);

/** @returns {"runtime" | "special" | "normal"} */
function permissionTier(name) {
  if (RUNTIME_PERMISSIONS.has(name)) return "runtime";
  if (SPECIAL_ACCESS_PERMISSIONS.has(name)) return "special";
  return "normal";
}

module.exports = { DANGEROUS_PERMISSIONS, RUNTIME_PERMISSIONS, SPECIAL_ACCESS_PERMISSIONS, permissionTier };
