"""Anchor extension for decision-bound-output-v1: WITNESS ORDER.

The open extension decision_bound.py names (accepted 2026-10-14, built by
babyblueviper1 / invinoveritas): decision-bound-output-v1 proves by hash
dependency that a bound output_hash could not exist before its decision's
content existed, but "it does not prevent the dispatcher from fabricating
BOTH the decision and the bound output at the same time, after the fact".
An independent publication of decision_id BEFORE the bound output_hash is
published adds a time the dispatcher cannot have influenced.

WHAT AN ANCHOR IS HERE. An OpenTimestamps proof (Bitcoin) or an RFC 3161
token over a 32-byte digest: the hex of claimed_decision_id (decision
anchor) or of recorded_output_hash (output anchor), exactly as they appear
after the "sha256:" prefix -- no further hashing. Every anchor is an UPPER
BOUND: "this digest existed no later than T". Nothing in either system
gives a lower bound.

WHAT THIS ESTABLISHES (code DECISION_WITNESSED_FIRST): the decision was
independently witnessed before the bound output was first witnessed. With
the hash dependency, that rules out the case the base mechanism leaves
open: a decision written up after the effect was already public and
back-cited. Ordering is decided only beyond the anchors' own error:
  * OTS vs OTS: Bitcoin block heights. A commitment in block h_d existed
    before block h_w > h_d was mined; the same block is not an order.
  * RFC 3161 vs RFC 3161: genTime_d + acc_d < genTime_w - acc_w, where acc
    is the token's own `accuracy`, or `tolerance_s` (default 60 s) when the
    token states none.
  * Across kinds: an OTS anchor is its block header time with a 7200 s
    tolerance (Bitcoin's two-hour rule).
The two non-OTS defaults are the ones ERC-8434 section 7 fixes for
commitment-log anchors (OTS 7200 s; RFC 3161 `accuracy`, 60 s when absent),
so one tolerance rule serves both. The earliest anchor on each side is
compared (tightest bound for the decision, first public appearance for
the output).

WHAT THIS DOES NOT ESTABLISH:
  * write-after-decision. This extension orders COMMITMENTS, exactly like
    COMMITMENT_AFTER_DECISION: content already on disk can still be bound
    and anchored later (KNOWN-LIMITATION-COMMITMENT-NOT-WRITE is unchanged
    and has an anchored twin in the vectors, still DECISION_WITNESSED_FIRST).
    What identifies "the same write" across two commitments stays this
    repo's design call (condition (b) of the 2026-10-14 acceptance).
  * that a header is on the Bitcoin chain, or that a TSA signed its token,
    unless the reader also does the lookups named in anchor_ots.py and
    anchor_rfc3161.py. The vectors carry the header and the token so the
    arithmetic replays offline.

CHECK ORDER: verify_case() from verify_decision_bound.py runs FIRST and
unchanged. Anything but COMMITMENT_AFTER_DECISION is returned as is and no
anchor is read: an anchor adds a time to a sound binding, it cannot repair
a forged citation, a denied decision or a mismatched hash. Then per side:
every anchor must be over that side's digest (ANCHOR_DIGEST_MISMATCH
otherwise -- a proof over some other bytes is not evidence of anything
here), then ordering.

RESULT CODES (anchor stage):
  ANCHOR_INVALID                  an anchor does not parse, or its Bitcoin header does not hash to its block / carry its commitment
  ANCHOR_DIGEST_MISMATCH          an anchor parses but is over a different digest (or a non-SHA-256 imprint)
  ANCHOR_PENDING                  a side has no confirmed anchor (OTS not yet in a block, or no anchor at all)
  WITNESS_CONFLICT                one pair of anchors orders decision first, another orders it after, both beyond tolerance
  DECISION_WITNESSED_AFTER_OUTPUT the output was witnessed before the decision, beyond tolerance: backdating not excluded
  DECISION_WITNESSED_FIRST        the decision was witnessed before the output, beyond tolerance
  WITNESS_ORDER_UNRESOLVED        every comparable pair is within tolerance (same block, or genTimes inside the error)
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import anchor_ots
import anchor_rfc3161
from verify_decision_bound import verify_case

OTS_TOLERANCE_S = 7200.0
DEFAULT_TOLERANCE_S = 60.0
HERE = Path(__file__).resolve().parent


def _hex(prefixed: str) -> str:
    return prefixed.split(":", 1)[1] if ":" in prefixed else prefixed


def _side(side: dict, digest_hex: str, tolerance_s: float) -> tuple[list[dict], tuple[str, str] | None]:
    """Confirmed anchors of one side as [{kind, t, acc, height?}], or (_, (code, detail)) on the first bad anchor."""
    out = []
    for i, a in enumerate(side.get("ots") or []):
        try:
            atts = anchor_ots.read_proof(base64.b64decode(a["proof_base64"]), digest_hex)
        except (anchor_ots.OtsError, ValueError, KeyError) as e:
            code = "ANCHOR_DIGEST_MISMATCH" if "different digest" in str(e) else "ANCHOR_INVALID"
            return out, (code, f"ots[{i}]: {e}")
        btc = a.get("bitcoin")
        hits = [x for x in atts if x["kind"] == "bitcoin" and btc and x["height"] == btc.get("height")]
        if not hits:
            continue                                       # pending (or a header not supplied): no bound from this proof
        try:
            t = anchor_ots.bitcoin_time(hits[0], btc["header_hex"], btc["block_hash"])
        except (anchor_ots.OtsError, KeyError, ValueError) as e:
            return out, ("ANCHOR_INVALID", f"ots[{i}]: {e}")
        out.append({"kind": "ots", "height": btc["height"], "t": float(t), "acc": OTS_TOLERANCE_S})
    for i, a in enumerate(side.get("rfc3161") or []):
        try:
            tok = anchor_rfc3161.read_token(base64.b64decode(a["token_base64"]))
        except (anchor_rfc3161.TstError, ValueError, KeyError) as e:
            return out, ("ANCHOR_INVALID", f"rfc3161[{i}]: {e}")
        if tok["hash_alg"] != "sha256" or tok["imprint_hex"] != digest_hex.lower():
            return out, ("ANCHOR_DIGEST_MISMATCH", f"rfc3161[{i}] ({a.get('tsa', '?')}): imprint is {tok['hash_alg']}:{tok['imprint_hex'][:16]}..., not this digest")
        if tok.get("status") not in (None, 0, 1):
            return out, ("ANCHOR_INVALID", f"rfc3161[{i}] ({a.get('tsa', '?')}): TSA status {tok['status']} is not granted")
        acc = tok["accuracy_s"] if tok["accuracy_s"] is not None else tolerance_s
        out.append({"kind": "rfc3161", "tsa": a.get("tsa"), "t": tok["gen_time_s"], "acc": acc})
    return out, None


def _order(d: dict, w: dict) -> int:
    """+1 decision first, -1 output first, 0 unresolved -- for one (decision anchor, output anchor) pair."""
    if d["kind"] == w["kind"] == "ots":
        return (d["height"] < w["height"]) - (d["height"] > w["height"])
    if d["t"] + d["acc"] < w["t"] - w["acc"]:
        return 1
    if w["t"] + w["acc"] < d["t"] - d["acc"]:
        return -1
    return 0


def verify_anchor_case(case: dict) -> dict:
    base = verify_case(case)
    if base["code"] != "COMMITMENT_AFTER_DECISION":
        return base
    tol = float(case.get("tolerance_s", DEFAULT_TOLERANCE_S))
    anchors = case.get("anchors") or {}
    sides = {}
    for name, digest in (("decision", _hex(case["claimed_decision_id"])), ("output", _hex(case["recorded_output_hash"]))):
        got, err = _side(anchors.get(name) or {}, digest, tol)
        if err:
            return {"case_id": case["case_id"], "code": err[0], "detail": f"{name} anchor {err[1]}"}
        sides[name] = got
    if not sides["decision"] or not sides["output"]:
        missing = [k for k in ("decision", "output") if not sides[k]]
        return {"case_id": case["case_id"], "code": "ANCHOR_PENDING",
                "detail": f"no confirmed anchor on the {' and '.join(missing)} side (an OTS proof still pending, or none given)"}
    # Earliest per kind and side: the decision's tightest upper bound (lowest block, lowest genTime + acc), the output's first
    # public appearance (lowest block, lowest genTime - acc). Same-kind pairs decide when they exist (heights are exact;
    # genTimes carry their own accuracy); cross-kind only otherwise.
    def earliest(anchors, sign):
        best = {}
        for a in anchors:
            key = a["height"] if a["kind"] == "ots" else a["t"] + sign * a["acc"]
            if a["kind"] not in best or key < best[a["kind"]][0]:
                best[a["kind"]] = (key, a)
        return {k: v[1] for k, v in best.items()}
    ed, eo = earliest(sides["decision"], +1), earliest(sides["output"], -1)
    pairs = [(ed[k], eo[k]) for k in ed if k in eo] or [(d, w) for d in ed.values() for w in eo.values()]
    votes = {_order(d, w) for d, w in pairs}
    kinds = sorted({d["kind"] for d, _ in pairs} | {w["kind"] for _, w in pairs})
    if 1 in votes and -1 in votes:
        return {"case_id": case["case_id"], "code": "WITNESS_CONFLICT",
                "detail": f"anchors disagree on the order beyond tolerance ({', '.join(kinds)}): one of the witnesses is wrong"}
    if -1 in votes:
        return {"case_id": case["case_id"], "code": "DECISION_WITNESSED_AFTER_OUTPUT",
                "detail": "the bound output was witnessed before its decision, beyond tolerance: the decision may have been "
                          "written after the effect was public (backdating not excluded)"}
    if 1 in votes:
        return {"case_id": case["case_id"], "code": "DECISION_WITNESSED_FIRST",
                "detail": f"decision witnessed before the bound output ({', '.join(kinds)}, beyond tolerance); orders commitments, "
                          "not the write (see KNOWN-LIMITATION-COMMITMENT-NOT-WRITE)"}
    return {"case_id": case["case_id"], "code": "WITNESS_ORDER_UNRESOLVED",
            "detail": f"every {'/'.join(kinds)} pair is within tolerance (same block, or genTimes inside accuracy {tol:g} s): "
                      "no order either way"}


def main() -> None:
    paths = [Path(p) for p in sys.argv[1:]] or sorted(HERE.glob("vectors_anchor*.json"))
    fails, n = [], 0
    for path in paths:
        for case in json.loads(path.read_text())["cases"]:
            r = verify_anchor_case(case)
            n += 1
            ok = r["code"] == case["expected_code"]
            print(f"{'ok  ' if ok else 'FAIL'} {case['case_id']:44s} {r['code']:32s} {r['detail'][:80]}")
            if not ok:
                fails.append(f"{path.name}:{case['case_id']}: expected {case['expected_code']}, got {r['code']}")
    if fails:
        print("\nFAILURES:\n  " + "\n  ".join(fails))
        sys.exit(1)
    print(f"\nALL {n} ANCHOR CHECKS PASS")


if __name__ == "__main__":
    main()
