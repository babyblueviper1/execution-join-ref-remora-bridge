"""Independent verifier for execution-join-ref-v1 over the REMORA/Observer
file-write bridge cases.

This does NOT trust build_vectors.py's precomputed preimages/refs -- it
recomputes every ref from the raw `source` fields each case carries (the
exact request dicts Observer retained, plus the grant's issuedAt/profile and
executionDigest) and only then compares against the claimed values. A
builder bug that wrote a wrong ref but a right-looking preimage would be
caught here.

Checks implemented, each mapped to execution-join-ref-v1
(docs/spec/execution-join-ref-v1.md, giskard09/argentum-core):

- canonical_envelope (invariant 1): every ref recomputes as
  SHA-256(JCS(its declared preimage)).
- chain_integrity (invariant 2, partial): decision_preimage.action_ref ==
  the APPROVED action_ref.
- effective_call_binding (invariant 6): if effective_action_ref !=
  approved_action_ref, a decision covering the effective ref must exist AND
  authorize it (outcome == "permit", see covering_decision_verdict() --
  fixed 2026-10-10, bug found by babyblueviper1: a covering decision that
  recomputed and bound to effective_action_ref but denied it used to still
  return AUTHORIZED_EFFECTIVE_CALL, because outcome was never read).
  None of AR-01/02/03 produce a covering decision at all ->
  EFFECTIVE_CALL_REBINDING_FAILED; COVERING-DENY (synthetic) produces one
  that denies -> the same code, for the reason covering_decision_verdict()
  gives.
- POST_COMMIT_DIVERGENCE (NEW, proposed -- NOT part of execution-join-ref-v1
  today): a post_commit_observation whose observed_hash differs from the
  result_id's committed output_hash for the same scope. This code does not
  exist in the spec's failure taxonomy; we are proposing it, not reporting
  an already-adopted result. See PROVENANCE.md.
- AR-04 is explicitly reported NOT_MODELED, never forced through invariant 6.
- MISSING-OBSERVATION: absence of a later read is reported UNKNOWN, never
  inferred as "unchanged".
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from jcs import jcs_bytes

VERSION = "execution-join-ref-v1"
CANON_PROFILE_ID = "f018a62879ab01f21e8fe5e9e7486dadba0b795e9358b32fd24d38d2c1f1f07d"
EXECUTOR_ID = "probity-protected-dispatcher"
# Declared convention (not discoverable from the source records): the
# attempt happens 500ms after the decision, the terminal result 1000ms
# after. Observer's retained JSON carries no attempt/write timestamp.
ATTEMPT_OFFSET_MS = 500
RESULT_OFFSET_MS = 1000


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ref(preimage: dict) -> str:
    return "sha256:" + sha256_hex(jcs_bytes(preimage))


def iso_to_ms(iso: str) -> int:
    dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def action_ref_preimage(request: dict, ts_ms: int) -> dict:
    return {
        "actor_id": request["principal_id"],
        "input_hash": "sha256:" + request["content_sha256"],
        "scope": f"{request['tool_id']}:{request['target_path']}",
        "ts_ms": ts_ms,
        "version": VERSION,
    }


class Fail(Exception):
    pass


def recompute_action_ref(request: dict, ts_ms: int) -> str:
    return ref(action_ref_preimage(request, ts_ms))


def covering_decision_verdict(covering: dict, effective_ref: str) -> tuple[str, str]:
    """Validates covering_decision_for_effective_ref structurally (recomputes and binds
    to effective_ref -- a Fail if either does not hold, same as before), then checks
    whether its outcome actually authorizes the call.

    Fixed 2026-10-10 (bug found by babyblueviper1, mutation testing against
    giskard09/execution-join-ref-remora-bridge@f900615): until this fix, both call
    sites checked only that the covering decision recomputes and binds to
    effective_action_ref, never its `outcome`. A covering decision with
    outcome="deny" -- a recorded REJECTION -- still produced AUTHORIZED_EFFECTIVE_CALL,
    because nothing read the field. `outcome` is part of every decision_preimage
    (`permit | deny | defer`, docs/spec/execution-join-ref-v1.md:50) and is exactly
    what distinguishes a decision that authorizes a call from one that does not; a
    verifier that recomputes the preimage byte-for-byte but never reads one of its
    fields for the question that field exists to answer is checking the hash, not the
    decision.

    Returns (code, detail). AUTHORIZED_EFFECTIVE_CALL only when outcome == "permit".
    A structurally-binding covering decision whose outcome is "deny" or "defer"
    provides no authorization for the dispatched call -- reusing
    EFFECTIVE_CALL_REBINDING_FAILED for that case rather than inventing a new taxonomy
    code: execution-join-ref-v1 (docs/spec/execution-join-ref-v1.md) does not define a
    code for "a decision covers the ref but denies it", and this file already
    distinguishes a sanctioned code from a proposed, unadopted one elsewhere
    (POST_COMMIT_DIVERGENCE) rather than inventing silently -- this is the same
    discipline applied to reuse instead of invention. From the relying party's point
    of view the two cases are observably identical (nothing authorizes the effective
    call), even though internally one has no covering decision_id at all and the other
    has one that denies -- the detail string says which one actually happened. This gap
    in the taxonomy (no code distinguishing "denied" from "absent") is not fixed here;
    see PROVENANCE.md.
    """
    covering_id = ref(covering["preimage"])
    if covering_id != covering["decision_id"]:
        raise Fail("covering_decision_for_effective_ref.decision_id does not recompute from its own preimage")
    if covering["preimage"]["action_ref"] != effective_ref:
        raise Fail("covering_decision_for_effective_ref does not bind to the effective_action_ref")
    outcome = covering["preimage"].get("outcome")
    if outcome == "permit":
        return "AUTHORIZED_EFFECTIVE_CALL", "effective ref has its own recomputed, binding covering decision"
    return "EFFECTIVE_CALL_REBINDING_FAILED", (
        f"a decision_id covers the effective_action_ref and recomputes correctly, but its "
        f"outcome is {outcome!r}, not 'permit' -- a decision that denies or defers provides "
        f"no authorization for the dispatched call, the same observable consequence as no "
        f"covering decision at all"
    )


def verify_case(case: dict) -> dict:
    case_id = case["case_id"]

    if case.get("synthetic") and case_id == "CHANGED-PREIMAGE":
        real = recompute_action_ref(
            {
                "principal_id": "svc-payments",
                "content_sha256": "7f353fcc5bd01b84b3d7fb209f62246e2c05e2f913afdc68584a1e6c47776b91",
                "tool_id": "transfer_funds",
                "target_path": "/work/acct-2.txt",
            },
            1760000000000,
        )
        if real != case["real_action_ref"]:
            raise Fail("recomputed real_action_ref does not even match the vector's own claim")
        if case["claimed_action_ref"] == real:
            raise Fail("expected claimed_action_ref to diverge from the recomputed ref")
        return {"case_id": case_id, "code": "DIGEST_MISMATCH", "detail": "claimed action_ref does not recompute from its own preimage"}

    if case.get("synthetic") and case_id in ("APPROVED-REWRITE", "COVERING-DENY"):
        approved_request = {
            "principal_id": "svc-payments",
            "content_sha256": "7f353fcc5bd01b84b3d7fb209f62246e2c05e2f913afdc68584a1e6c47776b91",
            "tool_id": "transfer_funds",
            "target_path": "/work/acct-2.txt",
        }
        rewritten_request = {**approved_request, "target_path": "/work/acct-3.txt"}
        ts_ms = case["approved_action_ref_preimage"]["ts_ms"]
        approved_ref = recompute_action_ref(approved_request, ts_ms)
        effective_ref = recompute_action_ref(rewritten_request, ts_ms)
        if approved_ref != case["approved_action_ref"] or effective_ref != case["effective_action_ref"]:
            raise Fail(f"{case_id} action_ref(s) do not recompute from the hardcoded fixture requests")
        code, detail = covering_decision_verdict(case["covering_decision_for_effective_ref"], effective_ref)
        if case_id == "APPROVED-REWRITE" and code != "AUTHORIZED_EFFECTIVE_CALL":
            raise Fail("APPROVED-REWRITE is this fixture set's positive demonstration of invariant 6 -- "
                       f"its covering decision must authorize the effective call, got {code}")
        if case_id == "COVERING-DENY" and code == "AUTHORIZED_EFFECTIVE_CALL":
            raise Fail("COVERING-DENY's covering decision denies the effective call by construction -- "
                       "a verifier that returns AUTHORIZED_EFFECTIVE_CALL here has the bug this vector exists to catch")
        return {"case_id": case_id, "code": code, "detail": detail}

    if case.get("synthetic") and case_id == "MISSING-OBSERVATION":
        if case["post_commit_observation"] is not None:
            raise Fail("MISSING-OBSERVATION vector unexpectedly carries an observation")
        return {"case_id": case_id, "code": "LATER_STATE_UNKNOWN", "detail": "no later read supplied; later state is not inferred"}

    src = case["source"]
    decision_ts_ms = iso_to_ms(src["grant_issued_at_iso"])

    approved_ref = recompute_action_ref(src["approved_request"], decision_ts_ms)
    if approved_ref != case["approved_action_ref"]:
        raise Fail(f"approved_action_ref mismatch: recomputed {approved_ref} != claimed {case['approved_action_ref']}")

    effective_ref = recompute_action_ref(src["attempted_request"], decision_ts_ms)
    if effective_ref != case["effective_action_ref"]:
        raise Fail(f"effective_action_ref mismatch: recomputed {effective_ref} != claimed {case['effective_action_ref']}")

    decision_pre = {
        "action_ref": approved_ref,
        "canonicalization_profile_id": CANON_PROFILE_ID,
        "outcome": "permit",
        "policy_id": f"{src['grant_profile']}/{src['execution_digest']}",
        "ts_ms": decision_ts_ms,
    }
    decision_id = ref(decision_pre)
    if decision_id != case["decision_id"]:
        raise Fail(f"decision_id mismatch: recomputed {decision_id} != claimed {case['decision_id']}")

    # chain_integrity (invariant 2): the decision binds to the APPROVED ref,
    # never to the effective one -- that is exactly the distinction
    # invariant 6 needs downstream.
    if decision_pre["action_ref"] != approved_ref:
        raise Fail("chain_integrity: decision_id does not bind to the approved action_ref")

    rewritten = effective_ref != approved_ref

    if case_id == "AR-04":
        if rewritten:
            raise Fail("AR-04 was expected to have approved_action_ref == effective_action_ref under this preimage")
        return {
            "case_id": case_id, "code": "NOT_MODELED",
            "detail": "policy/context digest changed but is outside the action_ref preimage; invariant 6 does not apply here",
        }

    if rewritten:
        covering = case.get("covering_decision_for_effective_ref")
        if covering is not None:
            # Recompute THIS decision too -- a non-null value is not itself
            # evidence; it must actually bind to effective_ref, AND actually
            # authorize it (see covering_decision_verdict's docstring).
            code, detail = covering_decision_verdict(covering, effective_ref)
            return {"case_id": case_id, "code": code, "detail": detail}
        # Observer's own retained records show no second grant was ever
        # issued for the rewritten request in AR-01/02/03.
        return {
            "case_id": case_id, "code": "EFFECTIVE_CALL_REBINDING_FAILED",
            "detail": "decision covers the approved preimage; the effective (attempted) preimage differs and no decision covers it",
        }

    # Not rewritten: approved == effective. If there's a terminal result,
    # check it; then check for a post-commit divergence if one is supplied.
    if "result_preimage" not in case:
        raise Fail(f"{case_id}: unrewritten case with no terminal result -- unexpected shape")

    attempt_pre = {
        "action_ref": effective_ref,
        "attempt_seq": 1,
        "executor_id": EXECUTOR_ID,
        "ts_ms": decision_ts_ms + ATTEMPT_OFFSET_MS,
        "version": VERSION,
    }
    attempt_id = ref(attempt_pre)
    if attempt_id != case["attempt_id"]:
        raise Fail(f"attempt_id mismatch: recomputed {attempt_id} != claimed {case['attempt_id']}")

    output_hash = "sha256:" + src["approved_request"]["content_sha256"]
    result_pre = {
        "attempt_id": attempt_id,
        "outcome": "completed",
        "output_hash": output_hash,
        "ts_ms": decision_ts_ms + RESULT_OFFSET_MS,
        "version": VERSION,
    }
    result_id = ref(result_pre)
    if result_id != case["result_id"]:
        raise Fail(f"result_id mismatch: recomputed {result_id} != claimed {case['result_id']}")
    if output_hash != case["output_hash"]:
        raise Fail("output_hash mismatch")

    obs = case.get("post_commit_observation")
    if obs is None:
        return {"case_id": case_id, "code": "AUTHORIZED_EFFECTIVE_CALL", "detail": "join verified; no later observation supplied"}

    current_hash = "sha256:" + src["current_content_sha256"]
    if current_hash != obs["observed_hash"]:
        raise Fail("post_commit_observation.observed_hash does not match source.current_content_sha256")

    if current_hash == output_hash:
        return {"case_id": case_id, "code": "AUTHORIZED_EFFECTIVE_CALL", "detail": "join verified; later read still matches the committed output_hash"}

    return {
        "case_id": case_id, "code": "POST_COMMIT_DIVERGENCE",
        "detail": (
            f"result_id {result_id} committed output_hash {output_hash}; "
            f"a later read of the same scope ({obs['target_scope']}) observed {current_hash}. "
            "The original result is preserved, not overwritten."
        ),
    }


def main() -> None:
    vectors_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("vectors.json")
    data = json.loads(vectors_path.read_text())
    outcomes = []
    failures = []
    for case in data["cases"]:
        try:
            outcomes.append(verify_case(case))
        except Fail as exc:
            failures.append({"case_id": case["case_id"], "error": str(exc)})

    for o in outcomes:
        print(f"{o['case_id']:20s} {o['code']:28s} {o['detail']}")
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  {f['case_id']}: {f['error']}")
        sys.exit(1)
    print(f"\nALL {len(outcomes)} CHECKS PASS")


if __name__ == "__main__":
    main()
