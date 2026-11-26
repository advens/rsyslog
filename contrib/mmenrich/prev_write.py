#!/usr/bin/env python3
"""Writer for the prevalence lookup table (.prev), the C-reader contract.

Mirrors prev_format.h BYTE-FOR-BYTE: the same keyed SipHash-1-3, the same
open-addressing insert (0 = empty slot, real key hashing to 0 bumped to 1), the
same little-endian header + 16-byte entry layout. The 128-bit key is drawn at
random per table and stored in its header; readers hash with that key. A collector uses
this to turn per-observable counts aggregated from several hosts into the file each
host's mmenrich reads. Pure stdlib so it runs anywhere the collector does.

Run standalone to emit the conformance fixture that test_prev.c reads back:
    python3 prev_write.py /tmp/conformance.prev
"""
from __future__ import annotations

import struct
import sys

PREV_MAGIC = 0x50524556  # "PREV"
PREV_VERSION = 3
_MASK64 = (1 << 64) - 1
# Header: magic,version(u32,u32) total_size(u64) hash_slots,entry_count,checksum,
# epoch(u32*4) offset_entries(u64) count_max(u32) reporting_edges(u32)
# sip_key(u64*2) reserved(u32*4). '<' = LE. reporting_edges 0 means the writer
# did not say.
_HDR = struct.Struct("<IIQIIIIQIIQQ" + "I" * 4)
# hash_key(u64) total_count(u32) edge_count(u16) source_count(u16). The last u16
# was `flags` in v1 (always 0); v2 repurposes it to the distinct-internal-source
# count (same 16-byte layout, semantic-only change → version bump).
_ENTRY = struct.Struct("<QIHH")
assert _HDR.size == 80, _HDR.size
assert _ENTRY.size == 16, _ENTRY.size


def _rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & _MASK64


def siphash(k0: int, k1: int, data: bytes, c: int = 1, d: int = 3) -> int:
    """SipHash-c-d of data under (k0, k1); prev_siphash() in prev_format.h."""
    v0 = 0x736F6D6570736575 ^ k0
    v1 = 0x646F72616E646F6D ^ k1
    v2 = 0x6C7967656E657261 ^ k0
    v3 = 0x7465646279746573 ^ k1

    def rounds(n: int) -> None:
        nonlocal v0, v1, v2, v3
        for _ in range(n):
            v0 = (v0 + v1) & _MASK64
            v1 = _rotl(v1, 13) ^ v0
            v0 = _rotl(v0, 32)
            v2 = (v2 + v3) & _MASK64
            v3 = _rotl(v3, 16) ^ v2
            v0 = (v0 + v3) & _MASK64
            v3 = _rotl(v3, 21) ^ v0
            v2 = (v2 + v1) & _MASK64
            v1 = _rotl(v1, 17) ^ v2
            v2 = _rotl(v2, 32)

    full = len(data) - len(data) % 8
    for i in range(0, full, 8):
        m = int.from_bytes(data[i:i + 8], "little")
        v3 ^= m
        rounds(c)
        v0 ^= m
    b = (len(data) & 0xFF) << 56 | int.from_bytes(data[full:], "little")
    v3 ^= b
    rounds(c)
    v0 ^= b
    v2 ^= 0xFF
    rounds(d)
    return v0 ^ v1 ^ v2 ^ v3


def prev_hash(key: tuple[int, int], s: str) -> int:
    """Row key of an observable: prev_hash() in prev_format.h. Never 0."""
    return siphash(key[0], key[1], s.encode("utf-8")) or 1


def new_key() -> tuple[int, int]:
    """A random 128-bit table key."""
    import os
    raw = os.urandom(16)
    return int.from_bytes(raw[:8], "little"), int.from_bytes(raw[8:], "little")


def _next_pow2(n: int) -> int:
    p = 1
    while p < n:
        p <<= 1
    return p


def build_prev_table(counts: dict, epoch: int = 0, load_factor: float = 0.5,
                     reporting_edges: int = 0,
                     key: tuple[int, int] | None = None) -> bytes:
    """Serialize {observable: (total_count, edge_count, source_count)} into a .prev image.

    counts values may be an int (total_count; edge_count/source_count default to
    1) or a (total_count, edge_count[, source_count]) tuple. Slots = next pow2
    keeping the table under load_factor; entries placed by open-addressing
    identical to the C reader. key is the table key; None draws one.
    """
    if key is None:
        key = new_key()
    items = []
    for k, v in counts.items():
        if not k:
            continue
        if isinstance(v, int):
            fc, ec, sc = v, 1, 1
        else:
            fc = int(v[0])
            ec = int(v[1]) if len(v) > 1 else 1
            sc = int(v[2]) if len(v) > 2 else 1
        items.append((k, fc & 0xFFFFFFFF, ec & 0xFFFF, sc & 0xFFFF))

    slots = max(8, _next_pow2(int(len(items) / max(0.05, load_factor)) + 1))
    mask = slots - 1
    table = [(0, 0, 0, 0)] * slots  # (hash_key, total_count, edge_count, source_count)
    placed = 0
    count_max = 0
    for name, fc, ec, sc in items:
        h = prev_hash(key, name)
        idx = h & mask
        for _ in range(slots):
            hk = table[idx][0]
            if hk == 0 or hk == h:
                if hk == 0:
                    placed += 1
                table[idx] = (h, fc, ec, sc)
                break
            idx = (idx + 1) & mask
        if fc > count_max:
            count_max = fc

    offset_entries = _HDR.size
    total_size = offset_entries + slots * _ENTRY.size
    hdr = _HDR.pack(
        PREV_MAGIC, PREV_VERSION, total_size,
        slots, placed, 0, epoch & 0xFFFFFFFF,
        offset_entries, count_max, reporting_edges & 0xFFFFFFFF,
        key[0] & _MASK64, key[1] & _MASK64,
        *([0] * 4),
    )
    body = bytearray()
    for hk, fc, ec, sc in table:
        body += _ENTRY.pack(hk, fc, ec, sc)
    return hdr + bytes(body)


def write_prev_table(path: str, counts: dict, epoch: int = 0,
                     reporting_edges: int = 0,
                     key: tuple[int, int] | None = None) -> int:
    """Atomically write the .prev image; returns the byte size."""
    import os
    blob = build_prev_table(counts, epoch=epoch,
                            reporting_edges=reporting_edges, key=key)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return len(blob)


# Conformance fixture shared with test_prev.c: keep the two in lockstep.
# Tuples are (total_count, edge_count, source_count): common CDN/SaaS have many
# distinct sources; the lonely beacon has exactly one (the volume-invariant tell).
# The fixture's table key, fixed so the C tests can put their counters under
# it. Test data only: a real table draws its key with new_key().
CONFORMANCE_KEY = (0x0706050403020100, 0x0F0E0D0C0B0A0908)

CONFORMANCE = {
    "www.google.com": (50000, 7, 120),
    "cdn.cloudflare.net": (41000, 7, 95),
    "one.one.one.one": (12000, 6, 60),
    "internal.corp.lan": (800, 3, 12),
    "lonely-beacon.example": (2, 1, 1),
}

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/conformance.prev"
    n = write_prev_table(out, CONFORMANCE, epoch=1700000000, key=CONFORMANCE_KEY)
    print(f"wrote {out} ({n} bytes, {len(CONFORMANCE)} observables)")
