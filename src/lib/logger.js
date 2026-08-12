const chalk = require("chalk");

const logger = {
  title: (msg) => console.log(chalk.bold.cyanBright(msg)),
  info: (msg) => console.log(chalk.cyan("›"), msg),
  success: (msg) => console.log(chalk.green("✔"), msg),
  warn: (msg) => console.log(chalk.yellow("⚠"), msg),
  error: (msg) => console.log(chalk.red("✖"), msg),
  dim: (msg) => console.log(chalk.dim(msg)),
  section: (msg) => console.log("\n" + chalk.bold.white.bgBlack(` ${msg} `)),
  kv: (key, value) => console.log(chalk.dim(`  ${key}:`), chalk.white(value)),
};

module.exports = logger;
