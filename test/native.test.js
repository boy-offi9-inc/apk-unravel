const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { readElfLoadAlignment } = require("../src/lib/elf");
const { scanNativeLibs } = require("../src/lib/nativeLibs");
const { tmpdir, rmrf, write } = require("./_helpers");

/**
 * Builds a minimal but structurally valid ELF: header + program header table
 * with one PT_LOAD per requested alignment (plus a PT_DYNAMIC that must be
 * ignored). Supports 32/64-bit and both byte orders.
 */
function makeElf({ bits = 64, le = true, aligns = [0x4000] } = {}) {
  const ehsize = bits === 64 ? 64 : 52;
  const phentsize = bits === 64 ? 56 : 32;
  const types = [...aligns.map(() => 1), 2]; // PT_LOAD..., PT_DYNAMIC
  const alignVals = [...aligns, 0x1000]; // the dynamic segment's align must not matter
  const buf = Buffer.alloc(ehsize + phentsize * types.length);
  const w16 = (v, o) => (le ? buf.writeUInt16LE(v, o) : buf.writeUInt16BE(v, o));
  const w32 = (v, o) => (le ? buf.writeUInt32LE(v, o) : buf.writeUInt32BE(v, o));
  const w64 = (v, o) => (le ? buf.writeBigUInt64LE(BigInt(v), o) : buf.writeBigUInt64BE(BigInt(v), o));

  buf.writeUInt32BE(0x7f454c46, 0);
  buf[4] = bits === 64 ? 2 : 1;
  buf[5] = le ? 1 : 2;
  buf[6] = 1;
  if (bits === 64) {
    w64(ehsize, 32);
    w16(phentsize, 54);
    w16(types.length, 56);
  } else {
    w32(ehsize, 28);
    w16(phentsize, 42);
    w16(types.length, 44);
  }
  types.forEach((type, i) => {
    const base = ehsize + i * phentsize;
    w32(type, base);
    if (bits === 64) w64(alignVals[i], base + 48);
    else w32(alignVals[i], base + 28);
  });
  return buf;
}

test("elf: 16 KB and 64 KB aligned 64-bit libraries pass", async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  write(path.join(dir, "a.so"), makeElf({ aligns: [0x4000, 0x4000] }));
  write(path.join(dir, "b.so"), makeElf({ aligns: [0x10000] }));
  const a = await readElfLoadAlignment(path.join(dir, "a.so"));
  const b = await readElfLoadAlignment(path.join(dir, "b.so"));
  assert.equal(a.valid && a.aligned16k, true);
  assert.deepEqual(a.loadAlignments, [0x4000]);
  assert.equal(b.aligned16k, true);
});

test("elf: any 4 KB PT_LOAD segment fails; PT_DYNAMIC alignment is ignored", async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  write(path.join(dir, "mixed.so"), makeElf({ aligns: [0x4000, 0x1000] }));
  write(path.join(dir, "old.so"), makeElf({ aligns: [0x1000] }));
  const mixed = await readElfLoadAlignment(path.join(dir, "mixed.so"));
  assert.equal(mixed.aligned16k, false);
  assert.deepEqual(mixed.loadAlignments, [0x1000, 0x4000]);
  assert.equal((await readElfLoadAlignment(path.join(dir, "old.so"))).aligned16k, false);
});

test("elf: 32-bit and big-endian layouts are parsed", async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  for (const [name, opts, expected] of [
    ["le32.so", { bits: 32, aligns: [0x1000] }, false],
    ["le32ok.so", { bits: 32, aligns: [0x4000] }, true],
    ["be64.so", { bits: 64, le: false, aligns: [0x4000] }, true],
    ["be32.so", { bits: 32, le: false, aligns: [0x1000] }, false],
  ]) {
    write(path.join(dir, name), makeElf(opts));
    const r = await readElfLoadAlignment(path.join(dir, name));
    assert.equal(r.valid, true, name);
    assert.equal(r.aligned16k, expected, name);
  }
});

test("elf: junk, truncated and missing files are reported invalid, never thrown", async (t) => {
  const dir = tmpdir();
  t.after(() => rmrf(dir));
  write(path.join(dir, "junk.so"), "this is not an elf file at all, just text padding.............");
  write(path.join(dir, "trunc.so"), makeElf({ aligns: [0x4000] }).subarray(0, 70));
  write(path.join(dir, "empty.so"), "");
  for (const name of ["junk.so", "trunc.so", "empty.so", "missing.so"]) {
    const r = await readElfLoadAlignment(path.join(dir, name));
    assert.equal(r.valid, false, name);
    assert.ok(r.error, name);
  }
});

test("scanNativeLibs: flags unaligned 64-bit libs only, lists them, and notes the zip-alignment caveat", async (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  write(path.join(root, "lib/arm64-v8a/libgood.so"), makeElf({ aligns: [0x4000] }));
  write(path.join(root, "lib/arm64-v8a/libbad.so"), makeElf({ aligns: [0x1000] }));
  write(path.join(root, "lib/arm64-v8a/libjunk.so"), "not elf");
  write(path.join(root, "lib/armeabi-v7a/libold32.so"), makeElf({ bits: 32, aligns: [0x1000] })); // 32-bit: exempt

  const res = await scanNativeLibs(root);
  const arm64 = res.abis.find((a) => a.abi === "arm64-v8a");
  assert.deepEqual(arm64.unaligned16k, ["libbad.so"]);
  assert.deepEqual(arm64.unreadable, ["libjunk.so"]);
  assert.equal(arm64.alignment["libgood.so"].aligned16k, true);

  const flags = res.flags.filter((f) => f.flag === "unaligned16kPageSize");
  assert.equal(flags.length, 1, "armeabi-v7a must not be flagged");
  assert.match(flags[0].detail, /1 of 3 arm64-v8a library has/);
  assert.match(flags[0].detail, /libbad\.so/);
  assert.match(flags[0].detail, /zip-aligned/);
});

test("scanNativeLibs: fully aligned 64-bit build raises no 16 KB flag", async (t) => {
  const root = tmpdir();
  t.after(() => rmrf(root));
  write(path.join(root, "lib/arm64-v8a/liba.so"), makeElf({ aligns: [0x4000] }));
  write(path.join(root, "lib/x86_64/liba.so"), makeElf({ aligns: [0x10000] }));
  const res = await scanNativeLibs(root);
  assert.ok(!res.flags.some((f) => f.flag === "unaligned16kPageSize"));
});
