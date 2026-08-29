const { Command } = require("commander");
const pkg = require("../package.json");
const decompileCommand = require("./commands/decompile");
const doctorCommand = require("./commands/doctor");
const { printBanner } = require("./lib/banner");

printBanner();

const program = new Command();

program
  .name("apk-unravel")
  .description(pkg.description)
  .version(pkg.version);

program
  .command("decompile <apk>")
  .description("Run apktool + jadx on an APK and generate a readable analysis report")
  .option("-o, --output <dir>", "output directory (default: ./apk-unravel-out/<apk-name>)")
  .option("--apktool-only", "only run apktool (skip jadx)")
  .option("--jadx-only", "only run jadx (skip apktool + manifest report)")
  .option("--no-smali", "with apktool, skip smali disassembly and only pull resources/manifest (faster)", false)
  .option("--deobfuscate", "enable jadx's built-in deobfuscation pass")
  .option("--strings", "scan decompiled source for URLs and potential secrets (heuristic, best-effort)")
  .option(
    "-g, --grep <keywords>",
    'comma-separated custom keywords/regex to search for in decompiled source (e.g. "firebase,MyCompanyName,/api\\.example\\.[a-z]+/i"). Runs alongside --strings scanning.'
  )
  .option("--strings-out <path>", "write string/keyword scan findings to a separate file (.json or .csv, inferred from extension)")
  .action((apk, options) => {
    // commander maps --no-smali to options.smali === false
    decompileCommand(apk, { ...options, noSmali: options.smali === false });
  });

program
  .command("doctor")
  .description("Check that apktool, jadx, and Java are installed and reachable")
  .action(doctorCommand);

program.parseAsync(process.argv);
