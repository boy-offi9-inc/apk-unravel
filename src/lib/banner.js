const chalk = require("chalk");
const boxen = require("boxen");
const pkg = require("../../package.json");
const { getEnvironment } = require("./environment");

// Guards against printing more than once per process, regardless of call path.
let printed = false;

/**
 * Prints the apk-unravel startup banner. Called unconditionally at the top
 * of the CLI (see src/index.js) so it shows for every invocation, including
 * `--help` and a bare `apk-unravel` with no subcommand.
 *
 * Styling adapts per environment:
 *   - ci:              plain text, no box (log output, not a terminal)
 *   - windows-legacy:  ASCII-only box border (old cmd.exe can't render Unicode box-drawing)
 *   - termux:          same rounded box as default, with a small mobile marker in the byline
 *   - default:         full rounded box
 */
function printBanner() {
  if (printed) return;
  printed = true;

  const env = getEnvironment();

  const title = chalk.bold.magentaBright("apk") + chalk.bold.white("-") + chalk.bold.cyanBright("unravel");
  const tagline = chalk.dim(`v${pkg.version} · apktool + jadx, one clean pipeline`);
  const byline = chalk.dim(env === "termux" ? "boy-offi9-inc · nothing is black box · termux" : "boy-offi9-inc · nothing is black box");

  if (env === "ci") {
    console.log(`apk-unravel v${pkg.version}`);
    console.log("apktool + jadx, one clean pipeline\n");
    return;
  }

  const content = `${title}\n${tagline}\n${byline}`;

  console.log(
    boxen(content, {
      padding: { top: 0, bottom: 0, left: 1, right: 1 },
      margin: { top: 0, bottom: 1, left: 0, right: 0 },
      borderStyle: env === "windows-legacy" ? "classic" : "round",
      borderColor: "magenta",
    })
  );
}

module.exports = { printBanner };
