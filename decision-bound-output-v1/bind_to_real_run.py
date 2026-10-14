"""Binds decision-bound-output-v1 to a REAL probity_observer/REMORA run --
same source, same pins, same mapping conventions already fixed in
../build_vectors.py (action_ref_preimage / decision_preimage), applied to
AR-00 (the control case: full decision -> attempt -> terminal write chain,
the only case with a real completed write).

Source of the per-case record: a REAL run of
probityai/agent-evidence-observer, examples/remora_effect_bridge.py,
commit 04b495d823dbcc49fa47b28fe1ba359dba8d4553 (same pin as
../PROVENANCE.md), against REMORA vectors pinned at
darklordVirtual/REMORA-research commit b25e735d36590154ff53768b4d245ad4c7996f64
(sha256 f896178eac35aab8843f0902934f1433eb6dccb2a212fc4139a67890faaabd27 --
verified to match PROVENANCE.md's own pin before this run).

Run executed 2026-10-14 by the creator's explicit `!` (external,
untrusted-by-default code -- same rule as the original run that produced
../PROVENANCE.md). `--verify` passed first
({"status": "retained-cases-checked", ...}) before this script read a
single retained file.

This script does NOT modify or fork Observer -- it is a read-only overlay,
same pattern as ../build_vectors.py: it reads the real retained JSON
(approved-request.json / grant.json / attempt.json / approved-content.bin)
and computes what a dispatcher COULD HAVE bound its output_hash to under
decision-bound-output-v1, using the real decision/content values. The
actual Observer run still only produced the legacy (unbound) output_hash --
this demonstrates the mechanism retrofitted onto real data, not a claim
that Observer itself implements it.

OUTPUT SHAPE (fixed 2026-10-14, bug found by ogasurfproject-jpg's blind
read of 301b1dc): this writes two cases in the SAME shape
verify_decision_bound.py's verify_case() expects everywhere else
(case_id / content_sha256 / decision_preimage / claimed_decision_id /
recorded_output_hash / expected_code) -- one with recorded_output_hash
set to the legacy (as-Observer-actually-produced-it) form, one with it
set to the decision-bound form, both citing the same real
claimed_decision_id. Before this fix the file used a different shape
(a single record carrying both "decision_id" and two separate hash
fields side by side) that verify_decision_bound.py had never actually
been run against -- `python3 verify_decision_bound.py
vectors_decision_bound.json` only ever exercised the synthetic file, and
"ALL 5 CHECKS PASS" was reported without the real-run file ever passing
through the same verifier at all. See verify_decision_bound.py's own
module docstring for the fix to main() that prevents this specific class
of oversight from recurring silently.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from decision_bound import bound_output_hash, decision_id_from_preimage, legacy_output_hash

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from jcs import jcs_bytes  # noqa: E402

VERSION = "execution-join-ref-v1"
CANON_PROFILE_ID = "f018a62879ab01f21e8fe5e9e7486dadba0b795e9358b32fd24d38d2c1f1f07d"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ref(preimage: dict) -> str:
    return "sha256:" + sha256_hex(jcs_bytes(preimage))


def iso_to_ms(iso: str) -> int:
    dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def action_ref_preimage(request: dict, ts_ms: int) -> dict:
    # Same mapping as ../build_vectors.py's action_ref_preimage -- our own
    # choice, not Observer's or the spec's, documented there.
    return {
        "actor_id": request["principal_id"],
        "input_hash": "sha256:" + request["content_sha256"],
        "scope": f"{request['tool_id']}:{request['target_path']}",
        "ts_ms": ts_ms,
        "version": VERSION,
    }


def main() -> None:
    run_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/remora-run-decisionbound")
    case_dir = run_dir / "AR-00"

    request = json.loads((case_dir / "approved-request.json").read_text())
    grant = json.loads((case_dir / "grant.json").read_text())
    attempt = json.loads((case_dir / "attempt.json").read_text())
    content_bytes = (case_dir / "approved-content.bin").read_bytes()

    real_content_sha256 = sha256_hex(content_bytes)
    if real_content_sha256 != request["content_sha256"]:
        raise SystemExit("approved-content.bin does not hash to the retained request's content_sha256 -- refusing to proceed")

    decision_ts_ms = iso_to_ms(grant["issuedAt"])
    policy_id = f"{grant['profile']}/{attempt['executionDigest']}"

    approved_preimage = action_ref_preimage(request, decision_ts_ms)
    approved_action_ref = ref(approved_preimage)

    decision_preimage = {
        "action_ref": approved_action_ref,
        "canonicalization_profile_id": CANON_PROFILE_ID,
        "outcome": "permit",
        "policy_id": policy_id,
        "ts_ms": decision_ts_ms,
    }
    real_decision_id = decision_id_from_preimage(decision_preimage)

    legacy_hash = legacy_output_hash(real_content_sha256)
    bound_hash = bound_output_hash(real_content_sha256, real_decision_id)

    source = {
        "observer_commit": "04b495d823dbcc49fa47b28fe1ba359dba8d4553",
        "remora_commit": "b25e735d36590154ff53768b4d245ad4c7996f64",
        "remora_vectors_sha256": "f896178eac35aab8843f0902934f1433eb6dccb2a212fc4139a67890faaabd27",
        "approved_request": request,
        "grant_issued_at_iso": grant["issuedAt"],
        "grant_profile": grant["profile"],
        "execution_digest": attempt["executionDigest"],
    }

    as_observed = {
        "case_id": "AR-00-REAL-AS-OBSERVED",
        "synthetic": False,
        "source": source,
        "content_sha256": real_content_sha256,
        "decision_preimage": decision_preimage,
        "claimed_decision_id": real_decision_id,
        "recorded_output_hash": legacy_hash,
        "expected_code": "ORDERING_UNVERIFIABLE",
        "note": (
            "What Observer's real run actually produced today: output_hash is the "
            "legacy content-only commitment, decision_id is never folded in. Not a "
            "tampering finding -- this write simply predates the mechanism."
        ),
    }
    decision_bound = {
        "case_id": "AR-00-REAL-DECISION-BOUND",
        "synthetic": False,
        "source": source,
        "content_sha256": real_content_sha256,
        "decision_preimage": decision_preimage,
        "claimed_decision_id": real_decision_id,
        "recorded_output_hash": bound_hash,
        "expected_code": "COMMITMENT_AFTER_DECISION",
        "note": (
            "The same real content and the same real covering decision, retrofitted "
            "under decision-bound-output-v1 -- what the same write would have produced "
            "had the dispatcher folded decision_id into output_hash."
        ),
    }

    out_path = Path("vectors_decision_bound_real_run.json")
    out_path.write_text(json.dumps(
        {"profile": "decision-bound-output-v1-real-run", "cases": [as_observed, decision_bound]},
        indent=2, sort_keys=True,
    ))
    print(f"wrote {out_path}")
    print(f"content_sha256             = {real_content_sha256}")
    print(f"decision_id (real, cited)  = {real_decision_id}")
    print(f"legacy_output_hash         = {legacy_hash}")
    print(f"decision_bound_output_hash = {bound_hash}")


if __name__ == "__main__":
    main()
