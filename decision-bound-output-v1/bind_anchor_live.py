"""Builds vectors_anchor_live.json: decision-bound anchor cases over REAL
anchors (Bitcoin via OpenTimestamps, RFC 3161 tokens from FreeTSA and
DigiCert), from the run recorded in anchor_live/.

THE RUN (2026-10-18, babyblueviper1 / invinoveritas). The decision fields
are synthetic (this repo's preimage shape, a policy id naming this run);
the anchors are real. Order of events, each step only after the previous:
  1. decision_preimage built, decision_id computed, decision_id's hex
     anchored (anchor_live/decision.json, 11:57:26Z).
  2. live-1: a file written under that decision, bound output_hash
     computed and anchored 98 s later (anchor_live/write-1.json, 11:59:04Z).
     98 s is inside the 60 s + 60 s RFC 3161 default: a near-simultaneous
     pair, what fabricating both at once looks like.
  3. live-2: after the decision's OTS proof was confirmed in a Bitcoin
     block, a second file written under the same decision, bound and
     anchored (anchor_live/write-2.json). Its first anchor is necessarily
     a later block and hours later in genTime.
Anchors were obtained through POST https://api.babyblueviper.com/work-acceptance/criteria
with {"sha256": <digest hex>} (free, no account; it commits a hash first-wins
and returns two RFC 3161 tokens and an OTS proof). Nothing in the vectors
depends on trusting that service: the tokens are FreeTSA's and DigiCert's
own, the proofs replay to Bitcoin headers, and any other route to the same
calendars and TSAs gives equivalent anchors.

This script needs the network and `opentimestamps-client` (`ots upgrade`)
to complete pending proofs, and fetches each attested block's header from
mempool.space, checking it hashes to the block at that height. The verifier
(verify_decision_bound_anchor.py) needs neither.

    python3 bind_anchor_live.py && python3 verify_decision_bound_anchor.py vectors_anchor_live.json
"""
from __future__ import annotations

import base64
import calendar
import time
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

import anchor_ots
from decision_bound import bound_output_hash, decision_id_from_preimage

HERE = Path(__file__).resolve().parent
LIVE = HERE / "anchor_live"
MEMPOOL = "https://mempool.space/api"


def _get(url: str) -> str:
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "decision-bound-anchor"}), timeout=20).read().decode().strip()


def _upgrade(b64: str) -> str:
    ots = shutil.which("ots")
    if not ots:
        return b64
    with tempfile.TemporaryDirectory() as d:
        fn = os.path.join(d, "p.ots")
        open(fn, "wb").write(base64.b64decode(b64))
        subprocess.run([ots, "upgrade", fn], capture_output=True, timeout=180)
        return base64.b64encode(open(fn, "rb").read()).decode()


def ots_anchor(b64: str, digest_hex: str) -> dict:
    """{proof_base64[, bitcoin{height, block_hash, header_hex}]} with the header checked against mempool.space's chain."""
    b64 = _upgrade(b64)
    atts = anchor_ots.read_proof(base64.b64decode(b64), digest_hex)
    btc = sorted((a for a in atts if a["kind"] == "bitcoin"), key=lambda a: a["height"])
    out = {"proof_base64": b64}
    for a in btc:
        bh = _get(f"{MEMPOOL}/block-height/{a['height']}")
        hdr = _get(f"{MEMPOOL}/block/{bh}/header")
        anchor_ots.bitcoin_time(a, hdr, bh)                 # raises unless sha256d(header) = bh and merkle root = commitment
        out["bitcoin"] = {"height": a["height"], "block_hash": bh, "header_hex": hdr, "source": "mempool.space"}
        break
    return out


def anchors_of(rec: dict, digest_hex: str) -> dict:
    a = {"rfc3161": [{"tsa": t["tsa"], "token_base64": t["token_base64"]} for t in rec.get("rfc3161", []) if t.get("token_base64")]}
    if (rec.get("ots") or {}).get("proof_base64"):
        a["ots"] = [ots_anchor(rec["ots"]["proof_base64"], digest_hex)]
    return a


def main() -> None:
    dec = json.loads((LIVE / "decision.json").read_text())
    did = decision_id_from_preimage(dec["decision_preimage"])
    assert did == dec["decision_id"], "decision_id does not recompute"
    dec_anchors = anchors_of(dec["decision_anchor"], did.split(":", 1)[1])
    cases = []
    for k in (1, 2):
        wp = LIVE / f"write-{k}.json"
        if not wp.exists():
            print(f"write-{k}.json not there yet -- skipped")
            continue
        w = json.loads(wp.read_text())
        content = (LIVE / w["content_file"]).read_bytes()
        csha = hashlib.sha256(content).hexdigest()
        assert csha == w["content_sha256"], f"{w['content_file']} changed"
        oh = bound_output_hash(csha, did)
        assert oh == w["bound_output_hash"], "bound output_hash does not recompute"
        out_anchors = anchors_of(w["write_anchor"], oh.split(":", 1)[1])
        dh = (dec_anchors.get("ots") or [{}])[0].get("bitcoin", {}).get("height")
        wh = (out_anchors.get("ots") or [{}])[0].get("bitcoin", {}).get("height")
        gd = min(t["gen_time"] for t in dec["decision_anchor"]["rfc3161"] if t.get("gen_time"))
        gw = min(t["gen_time"] for t in w["write_anchor"]["rfc3161"] if t.get("gen_time"))
        # Expected code from the raw facts, by the rule (not from the verifier): one vote per kind both sides have confirmed --
        # blocks by height; genTimes against 60 s + 60 s (neither TSA states an accuracy: checked in anchor_rfc3161.read_token).
        gap = (calendar.timegm(time.strptime(gw, "%Y%m%d%H%M%SZ")) - calendar.timegm(time.strptime(gd, "%Y%m%d%H%M%SZ")))
        votes = set()
        if dh is not None and wh is not None:
            votes.add((dh < wh) - (dh > wh))
        votes.add(1 if gap > 120 else -1 if gap < -120 else 0)
        expected = ("WITNESS_CONFLICT" if {1, -1} <= votes else "DECISION_WITNESSED_AFTER_OUTPUT" if -1 in votes
                    else "DECISION_WITNESSED_FIRST" if 1 in votes else "WITNESS_ORDER_UNRESOLVED")
        cases.append({"case_id": f"ANCHOR-LIVE-{k}", "content_sha256": csha, "decision_preimage": dec["decision_preimage"],
                      "claimed_decision_id": did, "recorded_output_hash": oh, "anchors": {"decision": dec_anchors, "output": out_anchors},
                      "expected_code": expected,
                      "note": f"real anchors: decision block {dh} genTime {gd}; output block {wh} genTime {gw} ({gap} s apart)",
                      "source": {"content_file": f"anchor_live/{w['content_file']}", "decision_record": "anchor_live/decision.json",
                                 "write_record": f"anchor_live/{wp.name}", "anchored_via": "https://api.babyblueviper.com/work-acceptance/criteria"}})
    (HERE / "vectors_anchor_live.json").write_text(json.dumps({"profile": "decision-bound-output-v1-anchor-live", "cases": cases},
                                                              indent=1, sort_keys=True) + "\n")
    print(f"wrote vectors_anchor_live.json ({len(cases)} cases): " + ", ".join(f"{c['case_id']} {c['expected_code']}" for c in cases))


if __name__ == "__main__":
    sys.exit(main())
