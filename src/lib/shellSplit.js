/**
 * Splits a command-line fragment into an argv array the way a POSIX shell
 * would for the simple cases people actually type: whitespace separates
 * arguments, '...' and "..." group them, and a backslash escapes the next
 * character (outside single quotes). No expansion of any kind — nothing here
 * is ever passed to a shell.
 *
 * @throws {Error} on an unterminated quote or trailing backslash
 */
function splitArgs(input) {
  const args = [];
  let cur = "";
  let started = false;
  let quote = null;

  for (let i = 0; i < input.length; i++) {
    const c = input[i];
    if (quote === "'") {
      if (c === "'") quote = null;
      else cur += c;
    } else if (quote === '"') {
      if (c === '"') quote = null;
      else if (c === "\\" && i + 1 < input.length && /["\\]/.test(input[i + 1])) cur += input[++i];
      else cur += c;
    } else if (c === "'" || c === '"') {
      quote = c;
      started = true;
    } else if (c === "\\") {
      if (i + 1 >= input.length) throw new Error("trailing backslash");
      cur += input[++i];
      started = true;
    } else if (/\s/.test(c)) {
      if (started || cur) args.push(cur);
      cur = "";
      started = false;
    } else {
      cur += c;
      started = true;
    }
  }
  if (quote) throw new Error(`unterminated ${quote === "'" ? "single" : "double"} quote`);
  if (started || cur) args.push(cur);
  return args;
}

module.exports = { splitArgs };
