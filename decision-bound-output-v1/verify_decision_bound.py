"""Independent verifier for decision-bound-output-v1 (see decision_bound.py's
module docstring). Does NOT trust any vector's precomputed fields except
content_sha256 and decision_preimage (the two things a real independent
reader would actually have: the file itself, or its hash, and the decision
record from wherever it's logged) -- claimed_decision_id and
recorded_output_hash are exactly the two things being checked, never assumed
correct.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from decision_bound import bound_output_hash, decision_id_from_preimage, legacy_output_hash


class Fail(Exception):
    pass


def verify_case(case: dict) -> dict:
    case_id = case["case_id"]
    content_sha256 = case["content_sha256"]
    decision_preimage = case["decision_preimage"]
    claimed_decision_id = case["claimed_decision_id"]
    recorded_output_hash = case["recorded_output_hash"]

    real_decision_id = decision_id_from_preimage(decision_preimage)

    if claimed_decision_id != real_decision_id:
        return {
            "case_id": case_id, "code": "FORGED_DECISION_CITATION",
            "detail": (
                f"claimed decision_id {claimed_decision_id} does not recompute from the "
                f"decision_preimage given (recomputes to {real_decision_id}) -- the citation "
                "of which decision covers this write is wrong or fabricated"
            ),
        }

    expected_bound_hash = bound_output_hash(content_sha256, claimed_decision_id)
    expected_legacy_hash = legacy_output_hash(content_sha256)

    if recorded_output_hash == expected_bound_hash:
        outcome = decision_preimage.get("outcome")
        if outcome != "permit":
            return {
                "case_id": case_id, "code": "UNAUTHORIZED_BINDING",
                "detail": (
                    f"output is correctly bound to decision_id {claimed_decision_id}, which "
                    f"recomputes cleanly, but that decision's outcome is {outcome!r}, not "
                    "'permit' -- a denied or deferred decision authorizes nothing, even though "
                    "the binding itself is cryptographically sound"
                ),
            }
        return {
            "case_id": case_id, "code": "ORDERING_ESTABLISHED",
            "detail": (
                "output_hash recomputes as SHA-256(JCS({content_sha256, decision_id})); the "
                "write could not have produced this exact value without the cited decision's "
                "own content already existing -- precedence proven by hash dependency, no "
                "clock trusted"
            ),
        }

    if recorded_output_hash == expected_legacy_hash:
        return {
            "case_id": case_id, "code": "ORDERING_UNVERIFIABLE",
            "detail": (
                "output_hash is the legacy content-only commitment (no decision folded in) -- "
                "this write carries no mechanism to establish precedence; not a tampering "
                "finding, just an unbound write"
            ),
        }

    return {
        "case_id": case_id, "code": "BINDING_MISMATCH",
        "detail": (
            f"recorded_output_hash {recorded_output_hash} matches neither the bound form "
            f"(content + claimed decision_id {claimed_decision_id}) nor the legacy "
            "content-only form -- either a different decision_id was actually used to produce "
            "this output than the one cited, or the content/output was altered after binding"
        ),
    }


def main() -> None:
    vectors_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("vectors_decision_bound.json")
    data = json.loads(vectors_path.read_text())
    outcomes = []
    failures = []
    for case in data["cases"]:
        try:
            result = verify_case(case)
        except Fail as exc:
            failures.append({"case_id": case["case_id"], "error": str(exc)})
            continue
        outcomes.append(result)
        expected = case.get("expected_code")
        if expected and result["code"] != expected:
            failures.append({
                "case_id": case["case_id"],
                "error": f"expected {expected}, verifier returned {result['code']}",
            })

    for o in outcomes:
        print(f"{o['case_id']:28s} {o['code']:26s} {o['detail'][:90]}")
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  {f['case_id']}: {f['error']}")
        sys.exit(1)
    print(f"\nALL {len(outcomes)} CHECKS PASS")


if __name__ == "__main__":
    main()
