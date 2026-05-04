#!/usr/bin/env python3
"""Enlarge a heap pool in arm9 to give translated msg packs room.

Background
----------
The FPK loader behind the dynamic msg-pack helper (0x0205D9E8) routes
allocations to a pool selected by the caller's arg flag. For every msg
pack registration, that flag is 0, so msg pack data lands in **pool 0**,
which arm9 sizes at 0x2A800 (174080 bytes) via a single init at
0x02026EC8 (`mov r1, #0x2A800; bl 0x0202A090`).

Pool 0 is shared by msg packs and other r0=0 allocations. Translated
text inflates total msg payload past the headroom this pool was sized
for, and once it fills, subsequent allocations return garbage. The
per-monster stat working buffer happens to be allocated from this pool
during scene setup, so it reads from invalid memory and produces wildly
wrong stats (HP/MP/Atk/Agi/Wis blown up by hundreds to thousands; only
Wis-or-similar untouched stats happen to land where the aliased memory
contains zero).

Patch points (set --pool to choose):
  pool 0: arm9 RAM 0x02026EC8  (default; the msg-pack arena)
  pool 2: arm9 RAM 0x02043124  (scene-specific sub-pool, rarely needs growth)

Constraints:
  - new_size must be ARM rotated-imm encodable (multiples of 0x1000 are safe)
  - growth must not push pool's parent arena past its ceiling

Usage:
  grow_msg_pool.py [--pool 0] [--size 0x40000] [--in PATH] [--out PATH]
"""
import argparse, os, struct, subprocess, sys, tempfile
from pathlib import Path

ARM9_BASE = 0x02000000

# Pool patch sites. Pool 0 is the global arena that msg packs actually load
# into (the FPK loader threads `r0=0` through to the per-entry alloc), so
# this is the one to grow when translated text overruns the heap.
POOLS = {
    0: dict(ram=0x02026EC8, orig_inst=0xE3A01BAA, orig_size=0x2A800, rd=1),
    2: dict(ram=0x02043124, orig_inst=0xE3A04A19, orig_size=0x19000, rd=4),
}

NITRO_TRAILER = bytes.fromhex('2106c0de680b000000000000')
BLZ = str(Path(__file__).parent / 'blz.out')


def encode_mov_imm(rd, value):
    for rot in range(16):
        rotated = ((value << (2 * rot)) | (value >> (32 - 2 * rot))) & 0xFFFFFFFF if rot else value
        if rotated <= 0xFF:
            return 0xE3A00000 | (rd << 12) | (rot << 8) | rotated
    raise ValueError(f'value 0x{value:x} cannot be encoded as ARM rotated imm8')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pool', type=int, default=0, choices=sorted(POOLS),
                    help='which pool to resize (default 0 — the global msg arena)')
    ap.add_argument('--size', type=lambda s: int(s, 0), default=0x40000,
                    help='new pool size (default 0x40000 = 256KB for pool 0)')
    ap.add_argument('--in', dest='inp', default='Pro_ROM/arm9.bin')
    ap.add_argument('--out', default=None)
    args = ap.parse_args()
    out = args.out or args.inp

    if not os.path.isfile(BLZ):
        sys.exit(f'blz binary not found at {BLZ}')

    site = POOLS[args.pool]
    new_size = args.size
    new_inst = encode_mov_imm(site['rd'], new_size)
    PATCH_OFF = site['ram'] - ARM9_BASE
    ORIG_INST = site['orig_inst']
    ORIG_SIZE = site['orig_size']
    PATCH_RAM = site['ram']

    raw = Path(args.inp).read_bytes()
    if not raw.endswith(NITRO_TRAILER):
        sys.exit('input does not look like compressed arm9.bin (missing Nitro trailer)')

    # Decompress via arm9tool's flow: strip trailer, run blz -d
    stripped = raw[:-len(NITRO_TRAILER)]
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tf:
        tf.write(stripped); tmp = tf.name
    try:
        subprocess.run([BLZ, '-d', tmp], check=True, capture_output=True)
        dec = bytearray(Path(tmp).read_bytes())
    finally:
        os.unlink(tmp)

    cur = struct.unpack('<I', dec[PATCH_OFF:PATCH_OFF+4])[0]
    if cur != ORIG_INST:
        sys.exit(f'patch site has unexpected bytes 0x{cur:08x} (expected 0x{ORIG_INST:08x}); '
                 'arm9 may already be patched or layout has shifted')
    struct.pack_into('<I', dec, PATCH_OFF, new_inst)
    print(f'patched pool {args.pool} at {PATCH_RAM:#x}: 0x{cur:08x} -> 0x{new_inst:08x}  '
          f'(mov r{site["rd"]}, #0x{ORIG_SIZE:x} -> #{new_size:#x})')

    # Re-compress, using the same approach as arm9tool.compress
    PLAINTEXT_PREFIX = 0x4000
    MODULE_PARAMS_FILE_OFF = 0xb68
    COMPRESSED_END_OFF = 0x14
    prefix = bytearray(dec[:PLAINTEXT_PREFIX])
    body   = bytes(dec[PLAINTEXT_PREFIX:])
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tf:
        tf.write(body); tmp = tf.name
    try:
        subprocess.run([BLZ, '-eo', tmp], check=True, capture_output=True)
        comp_body = Path(tmp).read_bytes()
    finally:
        os.unlink(tmp)
    new_compressed_end = ARM9_BASE + PLAINTEXT_PREFIX + len(comp_body)
    mp_field = MODULE_PARAMS_FILE_OFF + COMPRESSED_END_OFF
    struct.pack_into('<I', prefix, mp_field, new_compressed_end)
    final = bytes(prefix) + comp_body + NITRO_TRAILER
    Path(out).write_bytes(final)
    print(f'wrote {out}: {len(final):#x} bytes')


if __name__ == '__main__':
    main()
