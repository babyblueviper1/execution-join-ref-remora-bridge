"""Builds vectors_decision_bound.json -- all self-authored, illustrating the
decision-bound-output-v1 mechanism (see decision_bound.py's module docstring
for what this answers and what it does not establish). None of these are
derived from a real Observer/REMORA run -- that would be the next step once
the mechanism itself is reviewed, same order as execution-join-ref-v1
originally shipped (spec/mechanism first, then a real-run binding).
"""
from __future__ import annotations

import json
from pathlib import Path

from decision_bound import bound_output_hash, decision_id_from_preimage, legacy_output_hash

CONTENT_SHA256 = "7f353fcc5bd01b84b3d7fb209f62246e2c05e2f913afdc68584a1e6c47776b91"
OTHER_CONTENT_SHA256 = "a1b2c3d4e5f60718293a4b5c6d7e8f9018273645a5b6c7d8e9f0a1b2c3d4e5f6"

DECISION_PREIMAGE = {
    "action_ref": "sha256:9c3d1f3a9e6b2d4c5a7e8f9012345678901234567890123456789012345678",
    "canonicalization_profile_id": "f018a62879ab01f21e8fe5e9e7486dadba0b795e9358b32fd24d38d2c1f1f07d",
    "outcome": "permit",
    "policy_id": "probity-protected-action-reference-v0/policy-A",
    "ts_ms": 1760000100000,
}

DENIED_DECISION_PREIMAGE = {**DECISION_PREIMAGE, "outcome": "deny"}

OTHER_DECISION_PREIMAGE = {
    "action_ref": "sha256:1111111111111111111111111111111111111111111111111111111111111",
    "canonicalization_profile_id": "f018a62879ab01f21e8fe5e9e7486dadba0b795e9358b32fd24d38d2c1f1f07d",
    "outcome": "permit",
    "policy_id": "probity-protected-action-reference-v0/policy-A",
    "ts_ms": 1760000050000,
}


def main() -> None:
    real_decision_id = decision_id_from_preimage(DECISION_PREIMAGE)
    denied_decision_id = decision_id_from_preimage(DENIED_DECISION_PREIMAGE)
    other_decision_id = decision_id_from_preimage(OTHER_DECISION_PREIMAGE)

    cases = []

    # 1. Properly bound, decision permits -> ORDERING_ESTABLISHED.
    cases.append({
        "case_id": "DECISION-BOUND-OK",
        "note": (
            "The write's output_hash is SHA-256(JCS({content_sha256, decision_id})), "
            "claimed decision_id recomputes from the given decision_preimage, and that "
            "decision's outcome is permit. This is the positive case: ordering is "
            "established by hash dependency alone."
        ),
        "content_sha256": CONTENT_SHA256,
        "decision_preimage": DECISION_PREIMAGE,
        "claimed_decision_id": real_decision_id,
        "recorded_output_hash": bound_output_hash(CONTENT_SHA256, real_decision_id),
        "expected_code": "ORDERING_ESTABLISHED",
    })

    # 2. Legacy shape -- today's AR-00..AR-05, no binding attempted at all.
    cases.append({
        "case_id": "DECISION-BOUND-LEGACY",
        "note": (
            "output_hash is the legacy content-only commitment (today's shape in "
            "../build_vectors.py). Not tampering -- the write simply predates or does "
            "not use this mechanism. Reported as unverifiable, never as a failure."
        ),
        "content_sha256": CONTENT_SHA256,
        "decision_preimage": DECISION_PREIMAGE,
        "claimed_decision_id": real_decision_id,
        "recorded_output_hash": legacy_output_hash(CONTENT_SHA256),
        "expected_code": "ORDERING_UNVERIFIABLE",
    })

    # 3. The citation itself is wrong: claimed_decision_id does not recompute
    #    from the decision_preimage given (someone cited a decision_id that
    #    isn't actually this decision's hash -- a forged or corrupted citation).
    cases.append({
        "case_id": "DECISION-BOUND-FORGED-CITATION",
        "note": (
            "claimed_decision_id is an arbitrary value that does not recompute "
            "from decision_preimage's own fields -- the citation of WHICH decision "
            "covers this write is itself wrong or fabricated, caught before even "
            "checking the output binding."
        ),
        "content_sha256": CONTENT_SHA256,
        "decision_preimage": DECISION_PREIMAGE,
        "claimed_decision_id": "sha256:" + "0" * 64,
        "recorded_output_hash": bound_output_hash(CONTENT_SHA256, "sha256:" + "0" * 64),
        "expected_code": "FORGED_DECISION_CITATION",
    })

    # 4. The citation is legitimate (claimed_decision_id recomputes fine from
    #    the decision_preimage given), but the actual recorded_output_hash was
    #    bound against a DIFFERENT decision_id entirely -- the write claims one
    #    decision but was really bound to another (or to none, consistently).
    cases.append({
        "case_id": "DECISION-BOUND-SUBSTITUTED",
        "note": (
            "claimed_decision_id correctly recomputes from decision_preimage (the "
            "citation is legitimate), but recorded_output_hash was actually computed "
            "against a different decision_id (other_decision_id) -- neither the bound "
            "form under the claimed id nor the legacy form matches. Someone swapped "
            "which decision the output is really bound to after citing this one."
        ),
        "content_sha256": CONTENT_SHA256,
        "decision_preimage": DECISION_PREIMAGE,
        "claimed_decision_id": real_decision_id,
        "recorded_output_hash": bound_output_hash(CONTENT_SHA256, other_decision_id),
        "expected_code": "BINDING_MISMATCH",
    })

    # 5. Correctly bound and correctly cited, but the cited decision itself
    #    denies the call -- same lesson as finding #6 in ../PROVENANCE.md
    #    (a covering decision must actually authorize, not just cover).
    cases.append({
        "case_id": "DECISION-BOUND-DENIED",
        "note": (
            "output_hash correctly binds to denied_decision_id, which recomputes "
            "cleanly from its own preimage -- but that decision's outcome is 'deny'. "
            "A denied decision cannot be the covering authority for a write that "
            "happened anyway, even though the binding itself is cryptographically "
            "sound. Same lesson as PROVENANCE.md finding #6 applied here."
        ),
        "content_sha256": CONTENT_SHA256,
        "decision_preimage": DENIED_DECISION_PREIMAGE,
        "claimed_decision_id": denied_decision_id,
        "recorded_output_hash": bound_output_hash(CONTENT_SHA256, denied_decision_id),
        "expected_code": "UNAUTHORIZED_BINDING",
    })

    out = {"profile": "decision-bound-output-v1", "cases": cases}
    Path("vectors_decision_bound.json").write_text(json.dumps(out, indent=2, sort_keys=True))
    print(f"wrote vectors_decision_bound.json ({len(cases)} cases)")


if __name__ == "__main__":
    main()
