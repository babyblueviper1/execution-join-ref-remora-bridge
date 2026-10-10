"""Derive execution-join-ref-v1 vectors from a REAL remora_effect_bridge.py run.

Source of the per-case records: probityai/agent-evidence-observer,
examples/remora_effect_bridge.py, run against the REMORA vectors pinned at
darklordVirtual/REMORA-research commit b25e735d36590154ff53768b4d245ad4c7996f64
(examples/request-effect-join/CASE-TABLE.md, probityai/agent-evidence-atlas).

This script does NOT invent any per-case outcome. It reads the retained
JSON files a real run produced (approved-request.json / grant.json /
attempt.json per case directory) and maps their fields onto the
execution-join-ref-v1 preimage shapes (docs/spec/execution-join-ref-v1.md,
giskard09/argentum-core). The mapping choices that spec leaves
implementation-defined (scope string shape, executor_id, ts_ms source,
decision policy_id) are fixed HERE and documented in PROVENANCE.md -- they
are our own choices, not something the source or the spec dictates.

Two additional vectors (CHANGED-PREIMAGE, MISSING-OBSERVATION) are
self-authored -- not derived from any run -- to cover the two CASE-TABLE.md
rows REMORA's AR-00..AR-05 do not exercise (digest-mismatch-on-claimed-ref,
and "no later read supplied"). They are marked "synthetic": true.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from jcs import jcs_bytes

VERSION = "execution-join-ref-v1"
CANON_PROFILE_ID = "f018a62879ab01f21e8fe5e9e7486dadba0b795e9358b32fd24d38d2c1f1f07d"  # jcs-rfc8785-v1
EXECUTOR_ID = "probity-protected-dispatcher"  # our own label for the component that ran the write


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ref(preimage: dict) -> str:
    return "sha256:" + sha256_hex(jcs_bytes(preimage))


def iso_to_ms(iso: str) -> int:
    dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def action_ref_preimage(request: dict, ts_ms: int) -> dict:
    return {
        "actor_id": request["principal_id"],
        "input_hash": "sha256:" + request["content_sha256"],
        "scope": f"{request['tool_id']}:{request['target_path']}",
        "ts_ms": ts_ms,
        "version": VERSION,
    }


def decision_preimage(action_ref_value: str, policy_id: str, ts_ms: int, outcome: str = "permit",
                      canonicalization_profile_id: str = CANON_PROFILE_ID) -> dict:
    return {
        "action_ref": action_ref_value,
        "canonicalization_profile_id": canonicalization_profile_id,
        "outcome": outcome,
        "policy_id": policy_id,
        "ts_ms": ts_ms,
    }


def attempt_preimage(effective_action_ref: str, attempt_seq: int, ts_ms: int) -> dict:
    return {
        "action_ref": effective_action_ref,
        "attempt_seq": attempt_seq,
        "executor_id": EXECUTOR_ID,
        "ts_ms": ts_ms,
        "version": VERSION,
    }


def result_preimage(attempt_id_value: str, outcome: str, output_hash: str, ts_ms: int) -> dict:
    return {
        "attempt_id": attempt_id_value,
        "outcome": outcome,
        "output_hash": output_hash,
        "ts_ms": ts_ms,
        "version": VERSION,
    }


def build_case(run_dir: Path, case_id: str) -> dict:
    case_dir = run_dir / case_id
    grant = load(case_dir / "grant.json")
    attempt = load(case_dir / "attempt.json")

    approved_request = grant["request"]
    attempted_request = attempt["request"]

    decision_ts_ms = iso_to_ms(grant["issuedAt"])
    policy_id = f"{grant['profile']}/{attempt['executionDigest']}"

    approved_preimage = action_ref_preimage(approved_request, decision_ts_ms)
    approved_action_ref = ref(approved_preimage)

    effective_preimage = action_ref_preimage(attempted_request, decision_ts_ms)
    effective_action_ref = ref(effective_preimage)

    decision_pre = decision_preimage(approved_action_ref, policy_id, decision_ts_ms)
    decision_id_value = ref(decision_pre)

    record = {
        "case_id": case_id,
        "synthetic": False,
        "source": {
            "observer_case_dir": case_id,
            "approved_request": approved_request,
            "attempted_request": attempted_request,
            "grant_issued_at_iso": grant["issuedAt"],
            "grant_profile": grant["profile"],
            "execution_digest": attempt["executionDigest"],
        },
        "approved_action_ref_preimage": approved_preimage,
        "approved_action_ref": approved_action_ref,
        "effective_action_ref_preimage": effective_preimage,
        "effective_action_ref": effective_action_ref,
        "decision_preimage": decision_pre,
        "decision_id": decision_id_value,
        "rewritten": effective_action_ref != approved_action_ref,
        "covering_decision_for_effective_ref": None,  # none of these cases obtain a fresh decision after rewrite
    }

    if "response" in attempt:
        # Dispatch actually happened: build attempt_id/result_id over the
        # EFFECTIVE preimage (== approved preimage when nothing was rewritten;
        # these are AR-00 and AR-05, where approved == attempted).
        attempt_pre = attempt_preimage(effective_action_ref, 1, decision_ts_ms + 500)
        attempt_id_value = ref(attempt_pre)
        output_hash = "sha256:" + approved_request["content_sha256"]
        result_pre = result_preimage(attempt_id_value, "completed", output_hash, decision_ts_ms + 1000)
        record["attempt_preimage"] = attempt_pre
        record["attempt_id"] = attempt_id_value
        record["result_preimage"] = result_pre
        record["result_id"] = ref(result_pre)
        record["output_hash"] = output_hash

    if case_id == "AR-05":
        # Post-commit observation: a later, independent read of the same
        # target. The real run retains the bytes it read back
        # (currentContentSha256) but not a timestamp for that re-read --
        # Observer's script does not record one. We do not invent one:
        # observed_at_ms stays null, same as CASE-TABLE.md's own rule
        # ("missing material stays missing rather than being filled from a
        # current configuration").
        record["source"]["current_content_sha256"] = attempt["currentContentSha256"]
        record["source"]["read_back_refusal"] = attempt["readBackRefusal"]
        record["post_commit_observation"] = {
            "target_scope": effective_preimage["scope"],
            "observed_hash": "sha256:" + attempt["currentContentSha256"],
            "observed_at_ms": None,
            "observer_id": EXECUTOR_ID,
        }

    if case_id == "AR-03":
        record["source_scope_note"] = (
            "Observer's own run labels this UNSUPPORTED/unsupported-exact-vector "
            "(no registered reachable alternate tool) -- but invariant 6 only "
            "depends on the preimage differing with no covering decision, so it "
            "still applies regardless of that labeling."
        )

    if case_id == "AR-04":
        record["out_of_scope_for_invariant_6"] = (
            "approved_action_ref == effective_action_ref (principal/path/tool "
            "unchanged); the refusal is driven by a policy/context digest that "
            "execution-join-ref-v1's action_ref preimage does not include. "
            "This case is NOT modeled by invariant 6 and we do not force it in."
        )

    return record


def build_approved_rewrite_vector() -> dict:
    """Self-authored. CASE-TABLE.md's 'Approved rewrite' row has no REMORA/
    Observer vector -- none of AR-00..AR-05 obtain a fresh decision after a
    rewrite. We construct one so invariant 6's PASS path (not just its
    failure path) is actually exercised by a real recomputed covering
    decision, not a truthy flag."""
    approved_request = {
        "principal_id": "svc-payments",
        "content_sha256": "7f353fcc5bd01b84b3d7fb209f62246e2c05e2f913afdc68584a1e6c47776b91",
        "target_path": "/work/acct-2.txt",
        "tool_id": "transfer_funds",
    }
    rewritten_request = {
        "principal_id": "svc-payments",
        "content_sha256": "7f353fcc5bd01b84b3d7fb209f62246e2c05e2f913afdc68584a1e6c47776b91",
        "target_path": "/work/acct-3.txt",  # destination changed after the first approval
        "tool_id": "transfer_funds",
    }
    ts_ms = 1760000100000
    second_decision_ts_ms = ts_ms + 200  # the guardrail re-evaluates before dispatch

    approved_preimage = action_ref_preimage(approved_request, ts_ms)
    approved_action_ref = ref(approved_preimage)
    effective_preimage = action_ref_preimage(rewritten_request, ts_ms)
    effective_action_ref = ref(effective_preimage)

    first_decision_pre = decision_preimage(approved_action_ref, "probity-protected-action-reference-v0/policy-A", ts_ms)
    second_decision_pre = decision_preimage(effective_action_ref, "probity-protected-action-reference-v0/policy-A", second_decision_ts_ms)

    return {
        "case_id": "APPROVED-REWRITE",
        "synthetic": True,
        "note": (
            "Self-authored, not derived from any run. The guardrail rewrote the "
            "destination path, then obtained a SECOND decision covering the "
            "rewritten (effective) preimage before dispatch -- invariant 6's "
            "PASS path."
        ),
        "approved_action_ref_preimage": approved_preimage,
        "approved_action_ref": approved_action_ref,
        "effective_action_ref_preimage": effective_preimage,
        "effective_action_ref": effective_action_ref,
        "decision_preimage": first_decision_pre,
        "decision_id": ref(first_decision_pre),
        "rewritten": True,
        "covering_decision_for_effective_ref": {
            "preimage": second_decision_pre,
            "decision_id": ref(second_decision_pre),
        },
    }


def build_covering_deny_vector() -> dict:
    """Self-authored. Found by babyblueviper1 (mutation testing against this repo's
    f900615, 2026-10-10): a covering decision that recomputes and binds to
    effective_action_ref but whose outcome is "deny" -- a recorded REJECTION, not an
    authorization -- used to still produce AUTHORIZED_EFFECTIVE_CALL, because verify.py
    checked that the decision covers the ref and never read what it decided. Same
    rewrite scenario as APPROVED-REWRITE (identical approved_request/rewritten_request/
    timestamps -- verify.py's hardcoded recomputation for both vectors is the same
    block), differing only in the second decision's outcome."""
    approved_request = {
        "principal_id": "svc-payments",
        "content_sha256": "7f353fcc5bd01b84b3d7fb209f62246e2c05e2f913afdc68584a1e6c47776b91",
        "target_path": "/work/acct-2.txt",
        "tool_id": "transfer_funds",
    }
    rewritten_request = {
        "principal_id": "svc-payments",
        "content_sha256": "7f353fcc5bd01b84b3d7fb209f62246e2c05e2f913afdc68584a1e6c47776b91",
        "target_path": "/work/acct-3.txt",
        "tool_id": "transfer_funds",
    }
    ts_ms = 1760000100000
    second_decision_ts_ms = ts_ms + 200

    approved_preimage = action_ref_preimage(approved_request, ts_ms)
    approved_action_ref = ref(approved_preimage)
    effective_preimage = action_ref_preimage(rewritten_request, ts_ms)
    effective_action_ref = ref(effective_preimage)

    first_decision_pre = decision_preimage(approved_action_ref, "probity-protected-action-reference-v0/policy-A", ts_ms)
    second_decision_pre = decision_preimage(
        effective_action_ref, "probity-protected-action-reference-v0/policy-A", second_decision_ts_ms, outcome="deny")

    return {
        "case_id": "COVERING-DENY",
        "synthetic": True,
        "note": (
            "Self-authored, not derived from any run. The guardrail re-evaluated the "
            "rewritten (effective) preimage before dispatch -- a decision_id exists, "
            "recomputes, and binds to effective_action_ref -- but that decision's "
            "outcome is 'deny'. This is invariant 6's rejected-cover path: a decision "
            "covers the ref without authorizing it. Before 2026-10-10 this vector would "
            "have scored AUTHORIZED_EFFECTIVE_CALL against a verifier that checked only "
            "binding, never outcome."
        ),
        "approved_action_ref_preimage": approved_preimage,
        "approved_action_ref": approved_action_ref,
        "effective_action_ref_preimage": effective_preimage,
        "effective_action_ref": effective_action_ref,
        "decision_preimage": first_decision_pre,
        "decision_id": ref(first_decision_pre),
        "rewritten": True,
        "covering_decision_for_effective_ref": {
            "preimage": second_decision_pre,
            "decision_id": ref(second_decision_pre),
        },
    }


def build_covering_unsupported_profile_vector() -> dict:
    """Self-authored. Defensive completeness, not a bug fix: added 2026-10-10 alongside
    the COVERING-DENY fix, but no vector or run ever exercised a covering decision under
    a different canonicalization_profile_id before this -- this verifier implements
    exactly one profile and never dispatched on the claim. Same rewrite scenario as
    APPROVED-REWRITE/COVERING-DENY, second decision has outcome="permit" (isolating this
    from the outcome check) but declares a profile this verifier does not implement."""
    approved_request = {
        "principal_id": "svc-payments",
        "content_sha256": "7f353fcc5bd01b84b3d7fb209f62246e2c05e2f913afdc68584a1e6c47776b91",
        "target_path": "/work/acct-2.txt",
        "tool_id": "transfer_funds",
    }
    rewritten_request = {
        "principal_id": "svc-payments",
        "content_sha256": "7f353fcc5bd01b84b3d7fb209f62246e2c05e2f913afdc68584a1e6c47776b91",
        "target_path": "/work/acct-3.txt",
        "tool_id": "transfer_funds",
    }
    ts_ms = 1760000100000
    second_decision_ts_ms = ts_ms + 200

    approved_preimage = action_ref_preimage(approved_request, ts_ms)
    approved_action_ref = ref(approved_preimage)
    effective_preimage = action_ref_preimage(rewritten_request, ts_ms)
    effective_action_ref = ref(effective_preimage)

    first_decision_pre = decision_preimage(approved_action_ref, "probity-protected-action-reference-v0/policy-A", ts_ms)
    second_decision_pre = decision_preimage(
        effective_action_ref, "probity-protected-action-reference-v0/policy-A", second_decision_ts_ms,
        canonicalization_profile_id="jcs-rfc8785-v2-draft")

    return {
        "case_id": "COVERING-UNSUPPORTED-PROFILE",
        "synthetic": True,
        "note": (
            "Self-authored, not derived from any run. Same rewrite as APPROVED-REWRITE: "
            "a second decision exists, recomputes, binds to effective_action_ref, and "
            "permits it -- but declares canonicalization_profile_id "
            "'jcs-rfc8785-v2-draft', a profile this verifier does not implement. "
            "Defensive completeness (UNSUPPORTED_CANONICAL_PROFILE, already in the spec's "
            "taxonomy), not a bug: before 2026-10-10 nothing checked this field at all, "
            "but no published vector or run ever declared a different profile either."
        ),
        "approved_action_ref_preimage": approved_preimage,
        "approved_action_ref": approved_action_ref,
        "effective_action_ref_preimage": effective_preimage,
        "effective_action_ref": effective_action_ref,
        "decision_preimage": first_decision_pre,
        "decision_id": ref(first_decision_pre),
        "rewritten": True,
        "covering_decision_for_effective_ref": {
            "preimage": second_decision_pre,
            "decision_id": ref(second_decision_pre),
        },
    }


def build_synthetic_vectors() -> list[dict]:
    base_request = {
        "principal_id": "svc-payments",
        "content_sha256": "7f353fcc5bd01b84b3d7fb209f62246e2c05e2f913afdc68584a1e6c47776b91",
        "target_path": "/work/acct-2.txt",
        "tool_id": "transfer_funds",
    }
    ts_ms = 1760000000000

    changed_preimage = action_ref_preimage(base_request, ts_ms)
    real_action_ref = ref(changed_preimage)
    claimed_action_ref = "sha256:" + "0" * 64  # a claimed ref that will not recompute

    changed_evidence = {
        "case_id": "CHANGED-PREIMAGE",
        "synthetic": True,
        "note": (
            "Self-authored, not derived from any run. A claimed action_ref that "
            "does not recompute from its own declared preimage -- DIGEST_MISMATCH, "
            "the existing code. This is deliberately NOT the post-commit case: "
            "the divergence is in the preimage fields themselves, recomputed at "
            "verification time, not in a live external resource re-read."
        ),
        "action_ref_preimage": changed_preimage,
        "claimed_action_ref": claimed_action_ref,
        "real_action_ref": real_action_ref,
    }

    missing_observation = {
        "case_id": "MISSING-OBSERVATION",
        "synthetic": True,
        "note": (
            "Self-authored. A supported original join (decision covers action_ref, "
            "attempt/result exist) with NO later read supplied. A verifier MUST "
            "report later state as unknown -- never infer the file is unchanged "
            "from the absence of a later observation."
        ),
        "approved_action_ref_preimage": changed_preimage,
        "approved_action_ref": real_action_ref,
        "post_commit_observation": None,
    }

    return [changed_evidence, missing_observation]


def main() -> None:
    run_dir = Path(sys.argv[1])
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("vectors.json")
    case_ids = ["AR-00", "AR-01", "AR-02", "AR-03", "AR-04", "AR-05"]
    cases = ([build_case(run_dir, cid) for cid in case_ids]
             + [build_approved_rewrite_vector(), build_covering_deny_vector(),
                build_covering_unsupported_profile_vector()]
             + build_synthetic_vectors())
    out_path.write_text(json.dumps({"profile": "execution-join-ref-v1-remora-bridge-v0", "cases": cases}, indent=2, sort_keys=True))
    print(f"wrote {out_path} ({len(cases)} cases)")


if __name__ == "__main__":
    main()
