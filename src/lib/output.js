const ora = require("ora");
const logger = require("./logger");

/**
 * True when the raw argv asks for machine-friendly output. Needed before
 * commander has parsed anything, because the startup banner prints first.
 */
function isQuietArgv(argv) {
  return argv.slice(2).some((a) => a === "--json" || a === "--quiet" || a === "-q");
}

/**
 * ora spinner in normal mode. In quiet mode a silent stand-in with the same
 * chainable surface: progress/success chatter is dropped, but warn()/fail()
 * text is still routed to stderr so problems are never hidden.
 */
function createSpinner(text, { quiet = false } = {}) {
  if (!quiet) return ora(text);
  const s = {
    start: () => s,
    succeed: () => s,
    info: () => s,
    warn: (msg) => {
      if (msg) logger.warn(msg);
      return s;
    },
    fail: (msg) => {
      if (msg) logger.error(msg);
      return s;
    },
  };
  return s;
}

module.exports = { isQuietArgv, createSpinner };
