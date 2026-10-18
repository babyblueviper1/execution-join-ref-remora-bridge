"""Stdlib-only OpenTimestamps proof reader for the decision-bound anchor
extension (see verify_decision_bound_anchor.py).

Reads a detached .ots file (the format `ots stamp` writes), checks that it
is over the expected 32-byte digest, replays every operation path, and
returns each attestation it reaches with the message (commitment) at that
point. No network, no third-party package: only hashlib.

What this does NOT do on its own: decide that a Bitcoin block header is
really part of the Bitcoin chain. `bitcoin_time()` checks that a header
given to it hashes to the block hash given with it and that the proof's
commitment is that header's merkle root; whether that block hash is at
that height on the real chain is one lookup against any node or explorer
(`bitcoin-cli getblockhash <height>`, or
https://mempool.space/api/block-height/<height>). A vector records the
header so the check replays offline; a verifier that has not done the
lookup has checked the proof's arithmetic, not its anchoring.

Format (python-opentimestamps, core/timestamp.py + core/op.py + core/notary.py):
  magic  = b"\\x00OpenTimestamps\\x00\\x00Proof\\x00\\xbf\\x89\\xe2\\xe8\\x84\\xe8\\x92\\x94"
  varuint major version (1), file-hash op tag, file digest, then a timestamp tree.
  tree   = (0xff item)* item ; item = 0x00 attestation | op-tag [varbytes arg] tree
  attestation = 8-byte tag + varbytes payload; Bitcoin payload = varuint height.
"""
from __future__ import annotations

import hashlib

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BITCOIN = bytes.fromhex("0588960d73d71901")
PENDING = bytes.fromhex("83dfe30d2ef90c8e")
LITECOIN = bytes.fromhex("06869a0d73d71b45")
UNARY = {0x02: lambda m: hashlib.sha1(m).digest(), 0x08: lambda m: hashlib.sha256(m).digest(),
         0xf2: lambda m: m[::-1], 0xf3: lambda m: m.hex().encode()}
BINARY = {0xf0: lambda m, a: m + a, 0xf1: lambda m, a: a + m}
# 0x03 RIPEMD160 and 0x67 KECCAK256 are valid OTS ops but are not in every hashlib build; a proof using one is refused
# (OtsError) rather than replayed wrongly. The public calendars only emit SHA-256 / append / prepend.
FILE_HASH_LEN = {0x08: 32, 0x02: 20}


class OtsError(ValueError):
    pass


class _R:
    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def byte(self) -> int:
        if self.i >= len(self.b):
            raise OtsError("truncated proof")
        self.i += 1
        return self.b[self.i - 1]

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise OtsError("truncated proof")
        self.i += n
        return self.b[self.i - n:self.i]

    def varuint(self) -> int:
        v, shift = 0, 0
        while True:
            c = self.byte()
            v |= (c & 0x7f) << shift
            if not c & 0x80:
                return v
            shift += 7
            if shift > 63:
                raise OtsError("varuint too long")

    def varbytes(self, limit: int = 8192) -> bytes:
        n = self.varuint()
        if n > limit:
            raise OtsError("varbytes too long")
        return self.take(n)


def _tree(r: _R, msg: bytes, out: list, depth: int = 0) -> None:
    if depth > 256:
        raise OtsError("proof nests too deep")
    while True:
        tag = r.byte()
        last = tag != 0xff
        if not last:
            tag = r.byte()
        if tag == 0x00:
            atag, payload = r.take(8), r.varbytes()
            att = {"kind": "unknown", "tag": atag.hex()}
            if atag == BITCOIN:
                att = {"kind": "bitcoin", "height": _R(payload).varuint()}
            elif atag == PENDING:
                att = {"kind": "pending", "uri": _R(payload).varbytes().decode("utf-8", "replace")}
            elif atag == LITECOIN:
                att = {"kind": "litecoin", "height": _R(payload).varuint()}
            att["msg"] = msg.hex()
            out.append(att)
        elif tag in UNARY:
            _tree(r, UNARY[tag](msg), out, depth + 1)
        elif tag in BINARY:
            _tree(r, BINARY[tag](msg, r.varbytes(4096)), out, depth + 1)
        else:
            raise OtsError(f"unsupported op 0x{tag:02x}")
        if last:
            return


def read_proof(raw: bytes, expected_digest_hex: str) -> list[dict]:
    """Every attestation in a detached .ots file, each with the commitment `msg` it attests. Raises OtsError when the file is
    malformed or is not over `expected_digest_hex` (the 32-byte digest the anchor claims to cover)."""
    r = _R(raw)
    if r.take(len(MAGIC)) != MAGIC:
        raise OtsError("not a detached OpenTimestamps proof")
    if r.varuint() != 1:
        raise OtsError("unknown proof version")
    op = r.byte()
    if op not in FILE_HASH_LEN:
        raise OtsError(f"unsupported file-hash op 0x{op:02x}")
    digest = r.take(FILE_HASH_LEN[op])
    if digest.hex() != expected_digest_hex.lower():
        raise OtsError("proof is over a different digest")
    out: list[dict] = []
    _tree(r, digest, out)
    if r.i != len(raw):
        raise OtsError("trailing bytes after the proof")
    return out


def bitcoin_time(att: dict, header_hex: str, block_hash_hex: str) -> int:
    """Header time (unix seconds) for a Bitcoin attestation, after checking: sha256d(header) is block_hash (display order) and the
    attested commitment is the header's merkle root. Raises OtsError otherwise. Chain membership of block_hash at att['height'] is the
    caller's lookup (see the module docstring)."""
    h = bytes.fromhex(header_hex)
    if len(h) != 80:
        raise OtsError("block header must be 80 bytes")
    if hashlib.sha256(hashlib.sha256(h).digest()).digest()[::-1].hex() != block_hash_hex.lower():
        raise OtsError("header does not hash to the given block hash")
    if h[36:68].hex() != att["msg"]:
        raise OtsError("commitment is not this header's merkle root")
    return int.from_bytes(h[68:72], "little")
