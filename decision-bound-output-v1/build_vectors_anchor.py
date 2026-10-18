"""Builds vectors_anchor.json: the SYNTHETIC cases for the decision-bound
anchor extension (verify_decision_bound_anchor.py). The live, real-anchor
cases are in vectors_anchor_live.json (bind_anchor_live.py).

Synthetic means: the OpenTimestamps proofs are real-format proofs over the
case's real digests, but they end in Bitcoin attestations to block headers
built here (merkle root = the proof's commitment); the RFC 3161 tokens are a
TimeStampResp carrying a real-format TSTInfo with no CMS signature. Both
replay through the stdlib readers exactly like real ones; neither would pass
the chain lookup or `openssl ts -verify`, and every synthetic anchor says so
(`"synthetic": true`). They exist to pin the ordering rule, not to claim
any time.

Base content and decision: DECISION-BOUND-OK, DECISION-BOUND-FORGED-CITATION,
DECISION-BOUND-DENIED, DECISION-BOUND-LEGACY-UNBOUND (or its legacy form)
and KNOWN-LIMITATION-COMMITMENT-NOT-WRITE from vectors_decision_bound.json,
unchanged; each anchored case only adds `anchors` (and `tolerance_s` where
the case is about it).

    python3 build_vectors_anchor.py && python3 verify_decision_bound_anchor.py
"""
from __future__ import annotations

import base64
import calendar
import copy
import hashlib
import json
from pathlib import Path

import anchor_ots

HERE = Path(__file__).resolve().parent
T0 = calendar.timegm((2026, 10, 18, 12, 0, 0))
H0 = 900000


def _varuint(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def _vb(b: bytes) -> bytes:
    return _varuint(len(b)) + b


def ots_proof(digest_hex: str, height: int | None, t: int, salt: bytes) -> dict:
    """Detached proof: append(salt) -> sha256 -> Bitcoin attestation at `height` (or a pending attestation when height is None),
    plus the synthetic 80-byte header whose merkle root is that commitment."""
    d = bytes.fromhex(digest_hex)
    msg = hashlib.sha256(d + salt).digest()
    if height is None:
        att = b"\x00" + anchor_ots.PENDING + _vb(_vb(b"https://synthetic.calendar.invalid"))
    else:
        att = b"\x00" + anchor_ots.BITCOIN + _vb(_varuint(height))
    raw = anchor_ots.MAGIC + _varuint(1) + b"\x08" + d + b"\xf0" + _vb(salt) + b"\x08" + att
    out = {"proof_base64": base64.b64encode(raw).decode(), "synthetic": True}
    if height is not None:
        hdr = (0x20000000).to_bytes(4, "little") + bytes(32) + msg + t.to_bytes(4, "little") + bytes.fromhex("1d00ffff")[::-1] + bytes(4)
        out["bitcoin"] = {"height": height, "header_hex": hdr.hex(),
                          "block_hash": hashlib.sha256(hashlib.sha256(hdr).digest()).digest()[::-1].hex()}
    return out


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + body


def _int(n: int) -> bytes:
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return _der(0x02, b)


def tsr(digest_hex: str, t: int, accuracy_s: int | None = None, serial: int = 1) -> dict:
    """Unsigned TimeStampResp {status granted, {id-ct-TSTInfo, [0] OCTET STRING TSTInfo}} -- TSTInfo per RFC 3161 2.4.2."""
    sha256 = _der(0x30, _der(0x06, bytes.fromhex("608648016503040201")) + b"\x05\x00")
    gen = _der(0x18, __import__("time").strftime("%Y%m%d%H%M%SZ", __import__("time").gmtime(t)).encode())
    acc = _der(0x30, _int(accuracy_s)) if accuracy_s is not None else b""
    info = _der(0x30, _int(1) + _der(0x06, bytes.fromhex("2a0304")) + _der(0x30, sha256 + _der(0x04, bytes.fromhex(digest_hex)))
                + _int(serial) + gen + acc)
    token = _der(0x30, bytes.fromhex("060b2a864886f70d0109100104") + _der(0xa0, _der(0x04, info)))
    raw = _der(0x30, _der(0x30, _int(0)) + token)
    return {"tsa": "synthetic", "token_base64": base64.b64encode(raw).decode(), "synthetic": True}


def _h(prefixed: str) -> str:
    return prefixed.split(":", 1)[1]


def main() -> None:
    base = {c["case_id"]: c for c in json.loads((HERE / "vectors_decision_bound.json").read_text())["cases"]}
    ok = base["DECISION-BOUND-OK"]
    dig_d, dig_o = _h(ok["claimed_decision_id"]), _h(ok["recorded_output_hash"])
    other = hashlib.sha256(b"some other bytes").hexdigest()
    cases = []

    def add(case_id, src, anchors, expected, note, **extra):
        c = copy.deepcopy(src)
        c.pop("expected_code", None)
        c.pop("note", None)
        c.update(case_id=case_id, anchors=anchors, expected_code=expected, note=note, **extra)
        cases.append(c)

    ots = lambda dg, h, t, s: ots_proof(dg, h, t, s.encode())
    add("ANCHOR-OTS-DECISION-FIRST", ok,
        {"decision": {"ots": [ots(dig_d, H0, T0, "d")]}, "output": {"ots": [ots(dig_o, H0 + 3, T0 + 1800, "o")]}},
        "DECISION_WITNESSED_FIRST", "decision in block h, output first seen in block h+3: block order is exact")
    add("ANCHOR-OTS-SAME-BLOCK", ok,
        {"decision": {"ots": [ots(dig_d, H0, T0, "d")]}, "output": {"ots": [ots(dig_o, H0, T0, "o")]}},
        "WITNESS_ORDER_UNRESOLVED", "both commitments in one block: what a dispatcher fabricating both at once produces -- no order")
    add("ANCHOR-OTS-OUTPUT-FIRST", ok,
        {"decision": {"ots": [ots(dig_d, H0 + 5, T0 + 3000, "d")]}, "output": {"ots": [ots(dig_o, H0 + 1, T0 + 600, "o")]}},
        "DECISION_WITNESSED_AFTER_OUTPUT", "the output was public four blocks before the decision: a back-cited decision is not excluded")
    add("ANCHOR-OTS-PENDING", ok,
        {"decision": {"ots": [ots(dig_d, None, T0, "d")]}, "output": {"ots": [ots(dig_o, H0 + 3, T0 + 1800, "o")]}},
        "ANCHOR_PENDING", "decision proof has only a calendar (pending) attestation: no bound yet, not a failure")
    add("ANCHOR-OTS-DIGEST-MISMATCH", ok,
        {"decision": {"ots": [ots(other, H0, T0, "d")]}, "output": {"ots": [ots(dig_o, H0 + 3, T0 + 1800, "o")]}},
        "ANCHOR_DIGEST_MISMATCH", "a valid proof over other bytes is not evidence about this decision")
    bad = ots(dig_d, H0, T0, "d")
    hb = bytearray(bytes.fromhex(bad["bitcoin"]["header_hex"])); hb[40] ^= 1
    bad["bitcoin"]["header_hex"] = hb.hex()
    bad["bitcoin"]["block_hash"] = hashlib.sha256(hashlib.sha256(bytes(hb)).digest()).digest()[::-1].hex()
    add("ANCHOR-OTS-HEADER-NOT-COMMITMENT", ok,
        {"decision": {"ots": [bad]}, "output": {"ots": [ots(dig_o, H0 + 3, T0 + 1800, "o")]}},
        "ANCHOR_INVALID", "header hashes to its block hash, but its merkle root is not the proof's commitment")
    add("ANCHOR-RFC3161-DECISION-FIRST", ok,
        {"decision": {"rfc3161": [tsr(dig_d, T0)]}, "output": {"rfc3161": [tsr(dig_o, T0 + 300)]}},
        "DECISION_WITNESSED_FIRST", "genTimes 300 s apart, no stated accuracy: beyond 60 s + 60 s")
    add("ANCHOR-RFC3161-WITHIN-DEFAULT-TOLERANCE", ok,
        {"decision": {"rfc3161": [tsr(dig_d, T0)]}, "output": {"rfc3161": [tsr(dig_o, T0 + 90)]}},
        "WITNESS_ORDER_UNRESOLVED", "90 s apart, no stated accuracy: inside the 60 s default on each side")
    add("ANCHOR-RFC3161-STATED-ACCURACY", ok,
        {"decision": {"rfc3161": [tsr(dig_d, T0, accuracy_s=1)]}, "output": {"rfc3161": [tsr(dig_o, T0 + 90, accuracy_s=1)]}},
        "DECISION_WITNESSED_FIRST", "same 90 s, but both tokens state accuracy 1 s: the token's own accuracy replaces the default")
    add("ANCHOR-RFC3161-WIDER-TOLERANCE", ok,
        {"decision": {"rfc3161": [tsr(dig_d, T0)]}, "output": {"rfc3161": [tsr(dig_o, T0 + 300)]}},
        "WITNESS_ORDER_UNRESOLVED", "300 s apart, verifier policy tolerance_s 600: unresolved under the stricter policy", tolerance_s=600)
    add("ANCHOR-RFC3161-DIGEST-MISMATCH", ok,
        {"decision": {"rfc3161": [tsr(dig_d, T0)]}, "output": {"rfc3161": [tsr(other, T0 + 300)]}},
        "ANCHOR_DIGEST_MISMATCH", "output token's imprint is another digest")
    add("ANCHOR-CROSS-KIND-FIRST", ok,
        {"decision": {"ots": [ots(dig_d, H0, T0, "d")]}, "output": {"rfc3161": [tsr(dig_o, T0 + 3 * 3600)]}},
        "DECISION_WITNESSED_FIRST", "no same-kind pair: block time + 7200 s still before genTime - 60 s")
    add("ANCHOR-CROSS-KIND-WITHIN-TOLERANCE", ok,
        {"decision": {"ots": [ots(dig_d, H0, T0, "d")]}, "output": {"rfc3161": [tsr(dig_o, T0 + 3600)]}},
        "WITNESS_ORDER_UNRESOLVED", "one hour apart across kinds: inside Bitcoin's two-hour rule")
    add("ANCHOR-CONFLICT", ok,
        {"decision": {"ots": [ots(dig_d, H0, T0, "d")], "rfc3161": [tsr(dig_d, T0 + 900)]},
         "output": {"ots": [ots(dig_o, H0 + 3, T0 + 1800, "o")], "rfc3161": [tsr(dig_o, T0)]}},
        "WITNESS_CONFLICT", "blocks say decision first, the TSA tokens say output first by 900 s: one witness is wrong")
    add("ANCHOR-OTS-EARLIEST-COUNTS", ok,
        {"decision": {"ots": [ots(dig_d, H0 + 10, T0 + 6000, "d2"), ots(dig_d, H0, T0, "d")]},
         "output": {"ots": [ots(dig_o, H0 + 5, T0 + 3000, "o")]}},
        "DECISION_WITNESSED_FIRST", "decision anchored twice (h, h+10), output at h+5: the earliest decision anchor is the bound")
    add("ANCHOR-OTS-HEIGHT-NOT-HEADER-TIME", ok,
        {"decision": {"ots": [ots(dig_d, H0, T0 + 600, "d")]}, "output": {"ots": [ots(dig_o, H0 + 1, T0, "o")]}},
        "DECISION_WITNESSED_FIRST", "header times are not monotonic (h+1 is stamped 600 s before h): OTS vs OTS orders by height")
    add("ANCHOR-FORGED-CITATION-NOT-READ", base["DECISION-BOUND-FORGED-CITATION"],
        {"decision": {"ots": [ots(dig_d, H0, T0, "d")]}, "output": {"ots": [ots(dig_o, H0 + 3, T0 + 1800, "o")]}},
        "FORGED_DECISION_CITATION", "base check first: anchors cannot repair a forged citation and are never read")
    add("ANCHOR-DENIED-NOT-READ", base["DECISION-BOUND-DENIED"],
        {"decision": {"ots": [ots(dig_d, H0, T0, "d")]}, "output": {"ots": [ots(dig_o, H0 + 3, T0 + 1800, "o")]}},
        "UNAUTHORIZED_BINDING", "a denied decision authorizes nothing, however early it was witnessed")
    leg = next(c for k, c in base.items() if c.get("expected_code") == "ORDERING_UNVERIFIABLE")
    add("ANCHOR-LEGACY-NOT-READ", leg,
        {"decision": {"ots": [ots(dig_d, H0, T0, "d")]}, "output": {"ots": [ots(dig_o, H0 + 3, T0 + 1800, "o")]}},
        "ORDERING_UNVERIFIABLE", "an unbound (legacy) output has no dependency for an anchor to add a time to")
    add("KNOWN-LIMITATION-COMMITMENT-NOT-WRITE-ANCHORED", base["KNOWN-LIMITATION-COMMITMENT-NOT-WRITE"],
        {"decision": {"ots": [ots(_h(base["KNOWN-LIMITATION-COMMITMENT-NOT-WRITE"]["claimed_decision_id"]), H0, T0, "d")]},
         "output": {"ots": [ots(_h(base["KNOWN-LIMITATION-COMMITMENT-NOT-WRITE"]["recorded_output_hash"]), H0 + 3, T0 + 1800, "o")]}},
        "DECISION_WITNESSED_FIRST", "anchors order the COMMITMENTS; content already written unbound before the decision still passes "
                                    "-- the same-write question stays open (this repo's call)")
    out = {"profile": "decision-bound-output-v1-anchor-synthetic", "cases": cases}
    (HERE / "vectors_anchor.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print(f"wrote vectors_anchor.json ({len(cases)} cases)")


if __name__ == "__main__":
    main()
