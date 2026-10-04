// Native fs.promises (not fs-extra) so the FileHandle API is the same on every
// Node version/fs-extra major.
const { promises: fsp } = require("fs");

const PT_LOAD = 1;
const PAGE_16K = 0x4000;
const MAX_PROGRAM_HEADERS = 512; // sanity cap against corrupt headers

/**
 * Reads just enough of an ELF file (header + program headers, a few hundred
 * bytes) to report its PT_LOAD segment alignments — no external tool needed,
 * so it works the same in Termux as anywhere else.
 *
 * A native library is 16 KB page-size compatible when every PT_LOAD segment
 * has p_align >= 0x4000. Older NDK builds default to 0x1000 (4 KB) and need to
 * be rebuilt (NDK r28+ aligns by default) or relinked with
 * -Wl,-z,max-page-size=16384.
 *
 * @returns {Promise<{valid: false, error: string} | {
 *   valid: true, bits: 32|64, littleEndian: boolean,
 *   loadAlignments: number[], aligned16k: boolean }>}
 */
async function readElfLoadAlignment(filePath) {
  let handle;
  try {
    handle = await fsp.open(filePath, "r");
    const header = Buffer.alloc(64);
    const { bytesRead } = await handle.read(header, 0, 64, 0);
    if (bytesRead < 52 || header.readUInt32BE(0) !== 0x7f454c46) return { valid: false, error: "not an ELF file" };

    const cls = header[4];
    const data = header[5];
    if ((cls !== 1 && cls !== 2) || (data !== 1 && data !== 2)) return { valid: false, error: "unsupported ELF class/endianness" };
    const bits = cls === 2 ? 64 : 32;
    const le = data === 1;
    const u16 = (b, o) => (le ? b.readUInt16LE(o) : b.readUInt16BE(o));
    const u32 = (b, o) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
    const u64 = (b, o) => Number(le ? b.readBigUInt64LE(o) : b.readBigUInt64BE(o));

    if (bits === 64 && bytesRead < 64) return { valid: false, error: "truncated ELF header" };
    const phoff = bits === 64 ? u64(header, 32) : u32(header, 28);
    const phentsize = u16(header, bits === 64 ? 54 : 42);
    const phnum = u16(header, bits === 64 ? 56 : 44);
    const minEntry = bits === 64 ? 56 : 32;
    if (!phnum || phentsize < minEntry || phnum > MAX_PROGRAM_HEADERS) return { valid: false, error: "no usable program headers" };

    const table = Buffer.alloc(phentsize * phnum);
    const read = await handle.read(table, 0, table.length, phoff);
    if (read.bytesRead < table.length) return { valid: false, error: "truncated program header table" };

    const loadAlignments = [];
    for (let i = 0; i < phnum; i++) {
      const base = i * phentsize;
      if (u32(table, base) !== PT_LOAD) continue;
      loadAlignments.push(bits === 64 ? u64(table, base + 48) : u32(table, base + 28));
    }
    if (!loadAlignments.length) return { valid: false, error: "no PT_LOAD segments" };

    return {
      valid: true,
      bits,
      littleEndian: le,
      loadAlignments: Array.from(new Set(loadAlignments)).sort((a, b) => a - b),
      aligned16k: loadAlignments.every((a) => a >= PAGE_16K),
    };
  } catch (err) {
    return { valid: false, error: err.code || err.message };
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

module.exports = { readElfLoadAlignment, PAGE_16K };
