"""Mutation battery for the anchor extension: every LAX verifier below must
fail at least one case in vectors_anchor.json. A mutation no vector catches
means the vectors under-specify the rule, the same discipline as this repo's
check_vector_drift.py.

    python3 check_anchor_mutations.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import verify_decision_bound_anchor as V

HERE = Path(__file__).resolve().parent
CASES = json.loads((HERE / "vectors_anchor.json").read_text())["cases"]


def _run() -> list[str]:
    return [c["case_id"] for c in CASES if V.verify_anchor_case(c)["code"] != c["expected_code"]]


def _patch(name, value):
    old = getattr(V, name)
    setattr(V, name, value)
    return lambda: setattr(V, name, old)


def m_no_tolerance():
    """genTimes compared raw: accuracy and the 60 s default ignored."""
    o = V._order
    def lax(d, w):
        if d["kind"] == w["kind"] == "ots":
            return o(d, w)
        return (d["t"] < w["t"]) - (d["t"] > w["t"])
    return _patch("_order", lax)


def m_same_block_ordered():
    """the same block counted as 'decision first'."""
    o = V._order
    return _patch("_order", lambda d, w: 1 if d["kind"] == w["kind"] == "ots" and d["height"] == w["height"] else o(d, w))


def m_header_time_not_height():
    """OTS vs OTS ordered by header time with no tolerance instead of height."""
    o = V._order
    return _patch("_order", lambda d, w: ((d["t"] < w["t"]) - (d["t"] > w["t"])) if d["kind"] == w["kind"] == "ots" else o(d, w))


def m_ignore_stated_accuracy():
    """always the default tolerance, even when the token states its accuracy."""
    rt = V.anchor_rfc3161.read_token
    def lax(raw):
        x = rt(raw); x["accuracy_s"] = None; return x
    old = V.anchor_rfc3161.read_token
    V.anchor_rfc3161.read_token = lax
    return lambda: setattr(V.anchor_rfc3161, "read_token", old)


def m_anchors_before_base():
    """anchors read first; the base check skipped whenever an anchor orders the decision first."""
    real = V.verify_case
    def lax(case):
        r = real(case)
        return dict(r, code="COMMITMENT_AFTER_DECISION") if case.get("anchors") else r
    return _patch("verify_case", lax)


def m_no_digest_check():
    """each proof/token accepted over whatever digest it carries."""
    import base64
    s = V._side
    def own_digest(kind, a):
        raw = base64.b64decode(a["proof_base64" if kind == "ots" else "token_base64"])
        if kind == "ots":
            r = V.anchor_ots._R(raw); r.take(len(V.anchor_ots.MAGIC)); r.varuint(); op = r.byte()
            return r.take(V.anchor_ots.FILE_HASH_LEN[op]).hex()
        return V.anchor_rfc3161.read_token(raw)["imprint_hex"]
    def lax_side(side, digest_hex, tol):
        out = []
        for kind in ("ots", "rfc3161"):
            for a in side.get(kind) or []:
                got, err = s({kind: [a]}, own_digest(kind, a), tol)
                if err:
                    return out, err
                out += got
        return out, None
    return _patch("_side", lax_side)


def m_no_header_check():
    """the Bitcoin header taken on trust (time read, merkle root not compared)."""
    old = V.anchor_ots.bitcoin_time
    V.anchor_ots.bitcoin_time = lambda att, hdr, bh: int.from_bytes(bytes.fromhex(hdr)[68:72], "little")
    return lambda: setattr(V.anchor_ots, "bitcoin_time", old)


def m_pending_counts():
    """a pending (calendar-only) proof treated as confirmed at the calendar's time."""
    s = V._side
    def lax_side(side, digest_hex, tol):
        out, err = s(side, digest_hex, tol)
        if not out and not err and side.get("ots"):
            out = [{"kind": "rfc3161", "t": 0.0, "acc": 0.0}]
        return out, err
    return _patch("_side", lax_side)


def m_latest_not_earliest():
    """the LATEST decision anchor compared instead of the earliest."""
    s = V._side
    def lax_side(side, digest_hex, tol):
        out, err = s(side, digest_hex, tol)
        if out and side is not None and out and all(a["kind"] == "ots" for a in out) and len(out) > 1:
            out = [max(out, key=lambda a: a["height"])]
        return out, err
    return _patch("_side", lax_side)


def m_conflict_resolved_first():
    """disagreeing witnesses silently resolved in the decision's favour."""
    o = V._order
    seen = []
    def lax(d, w):
        r = o(d, w); seen.append(r)
        return 1 if r == -1 and 1 in seen else r
    return _patch("_order", lax)


MUTATIONS = [m_no_tolerance, m_same_block_ordered, m_header_time_not_height, m_ignore_stated_accuracy, m_anchors_before_base,
             m_no_digest_check, m_no_header_check, m_pending_counts, m_latest_not_earliest, m_conflict_resolved_first]


def main() -> None:
    base = _run()
    if base:
        sys.exit(f"reference verifier fails {base}; fix that first")
    missed = []
    for m in MUTATIONS:
        undo = m()
        try:
            caught = _run()
        finally:
            undo()
        print(f"{'caught' if caught else 'MISSED':6s} {m.__name__:28s} {m.__doc__.strip()[:70]:72s} by {', '.join(caught[:3]) or '-'}")
        if not caught:
            missed.append(m.__name__)
    if missed:
        sys.exit(f"\n{len(missed)} mutation(s) not caught by any vector: {missed}")
    print(f"\n{len(MUTATIONS)}/{len(MUTATIONS)} mutations caught; {len(CASES)} vectors")


if __name__ == "__main__":
    main()
