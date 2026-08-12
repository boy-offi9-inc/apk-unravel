function isTermux() {
  return Boolean(process.env.TERMUX_VERSION) || /com\.termux/.test(process.env.PREFIX || "");
}

function isCI() {
  return Boolean(process.env.CI);
}

// Old Windows cmd.exe/conhost (not Windows Terminal, not a Terminal.app-style
// emulator) often can't render Unicode box-drawing characters cleanly.
function isWindowsLegacyConsole() {
  return process.platform === "win32" && !process.env.WT_SESSION && !process.env.TERM_PROGRAM;
}

function getEnvironment() {
  if (isCI()) return "ci";
  if (isTermux()) return "termux";
  if (isWindowsLegacyConsole()) return "windows-legacy";
  return "default";
}

module.exports = { isTermux, isCI, isWindowsLegacyConsole, getEnvironment };
