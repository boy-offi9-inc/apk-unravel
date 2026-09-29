const chalk = require("chalk");

// In quiet mode (--quiet / --json) everything meant for humans on stdout is
// suppressed so stdout carries only machine-readable output. Warnings and
// errors always go to stderr and are never silenced.
let quiet = false;
const human = (fn) => (...args) => {
  if (!quiet) fn(...args);
};

const logger = {
  setQuiet: (value) => {
    quiet = Boolean(value);
  },
  isQuiet: () => quiet,
  title: human((msg) => console.log(chalk.bold.cyanBright(msg))),
  info: human((msg) => console.log(chalk.cyan("›"), msg)),
  success: human((msg) => console.log(chalk.green("✔"), msg)),
  dim: human((msg) => console.log(chalk.dim(msg))),
  section: human((msg) => console.log("\n" + chalk.bold.white.bgBlack(` ${msg} `))),
  kv: human((key, value) => console.log(chalk.dim(`  ${key}:`), chalk.white(value))),
  blank: human(() => console.log()),
  warn: (msg) => console.error(chalk.yellow("⚠"), msg),
  error: (msg) => console.error(chalk.red("✖"), msg),
};

module.exports = logger;
