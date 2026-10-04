// Minimal ZIP reader (central directory + single-entry extraction), built on
// node:fs/zlib only. APKs, XAPKs and APKS are all ZIPs, and all we ever need
// is "list entries" and "pull one file out" — no reason to add a dependency
// that has to install on Termux.
//
// Not supported (reported as clear errors): ZIP64 (>4 GB / >65535 entries),
// encrypted entries, compression methods other than stored/deflate.
const { promises: fsp, createReadStream, createWriteStream } = require("fs");
const { Transform } = require("stream");
const { pipeline } = require("stream/promises");
const zlib = require("zlib");

const SIG_EOCD = 0x06054b50;
const SIG_CDIR = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32Update(crc, buf) {
  let c = ~crc >>> 0;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

/** True if the file starts with a ZIP local-file or empty-archive signature. */
async function hasZipMagic(file) {
  const fh = await fsp.open(file, "r");
  try {
    const b = Buffer.alloc(4);
    const { bytesRead } = await fh.read(b, 0, 4, 0);
    return bytesRead === 4 && b[0] === 0x50 && b[1] === 0x4b && ((b[2] === 3 && b[3] === 4) || (b[2] === 5 && b[3] === 6));
  } finally {
    await fh.close();
  }
}

/**
 * @returns {Promise<Array<{name: string, method: number, flags: number, crc: number,
 *   compressedSize: number, size: number, localOffset: number}>>}
 */
async function readZipEntries(file) {
  const fh = await fsp.open(file, "r");
  try {
    const { size: fileSize } = await fh.stat();
    if (fileSize < 22) throw new Error("file is too small to be a ZIP archive");

    const tailLen = Math.min(fileSize, 22 + 0xffff);
    const tail = Buffer.alloc(tailLen);
    await fh.read(tail, 0, tailLen, fileSize - tailLen);
    let eocd = -1;
    for (let i = tailLen - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === SIG_EOCD) {
        eocd = i;
        break;
      }
    }
    if (eocd === -1) throw new Error("no ZIP end-of-central-directory record (truncated or not a ZIP)");

    const total = tail.readUInt16LE(eocd + 10);
    const cdSize = tail.readUInt32LE(eocd + 12);
    const cdOffset = tail.readUInt32LE(eocd + 16);
    if (total === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      throw new Error("ZIP64 archives (>4 GB or >65535 entries) are not supported");
    }
    if (cdOffset + cdSize > fileSize) throw new Error("central directory points past end of file (truncated download?)");

    const cd = Buffer.alloc(cdSize);
    await fh.read(cd, 0, cdSize, cdOffset);

    const entries = [];
    let p = 0;
    for (let i = 0; i < total; i++) {
      if (p + 46 > cd.length || cd.readUInt32LE(p) !== SIG_CDIR) throw new Error("corrupt ZIP central directory");
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      entries.push({
        flags: cd.readUInt16LE(p + 8),
        method: cd.readUInt16LE(p + 10),
        crc: cd.readUInt32LE(p + 16),
        compressedSize: cd.readUInt32LE(p + 20),
        size: cd.readUInt32LE(p + 24),
        localOffset: cd.readUInt32LE(p + 42),
        name: cd.toString("utf8", p + 46, p + 46 + nameLen),
      });
      p += 46 + nameLen + extraLen + commentLen;
    }
    return entries;
  } finally {
    await fh.close();
  }
}

/** Extracts one entry to `dest`, verifying its CRC-32 and size. */
async function extractEntry(file, entry, dest) {
  if (entry.flags & 1) throw new Error(`"${entry.name}" is encrypted`);
  if (entry.method !== 0 && entry.method !== 8) throw new Error(`"${entry.name}" uses unsupported ZIP compression method ${entry.method}`);

  const fh = await fsp.open(file, "r");
  let dataStart;
  try {
    const lh = Buffer.alloc(30);
    await fh.read(lh, 0, 30, entry.localOffset);
    if (lh.readUInt32LE(0) !== SIG_LOCAL) throw new Error(`corrupt local header for "${entry.name}"`);
    dataStart = entry.localOffset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
  } finally {
    await fh.close();
  }

  let crc = 0;
  let written = 0;
  const verify = new Transform({
    transform(chunk, _enc, cb) {
      crc = crc32Update(crc, chunk);
      written += chunk.length;
      cb(null, chunk);
    },
    flush(cb) {
      if (written !== entry.size) return cb(new Error(`"${entry.name}": size mismatch (expected ${entry.size}, got ${written}) — archive is corrupt`));
      if (crc !== entry.crc) return cb(new Error(`"${entry.name}": CRC-32 mismatch — archive is corrupt`));
      cb();
    },
  });

  if (entry.compressedSize === 0) {
    await fsp.writeFile(dest, "");
    return;
  }
  const source = createReadStream(file, { start: dataStart, end: dataStart + entry.compressedSize - 1 });
  const stages = entry.method === 8 ? [source, zlib.createInflateRaw(), verify, createWriteStream(dest)] : [source, verify, createWriteStream(dest)];
  await pipeline(...stages);
}

/** Reads a small entry fully into memory (e.g. an XAPK manifest.json). */
async function readEntryText(file, entry, maxBytes = 1024 * 1024) {
  if (entry.size > maxBytes) throw new Error(`"${entry.name}" is unexpectedly large`);
  const tmp = `${file}.${process.pid}.${Date.now()}.entry`;
  try {
    await extractEntry(file, entry, tmp);
    return await fsp.readFile(tmp, "utf8");
  } finally {
    await fsp.rm(tmp, { force: true });
  }
}

module.exports = { hasZipMagic, readZipEntries, extractEntry, readEntryText, crc32Update };
