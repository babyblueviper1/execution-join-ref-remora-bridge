# PROVENANCE — execution-join-ref-v1 over the REMORA/Observer file-write bridge

## What this is

A verifier (`verify.py`) and vectors (`vectors.json`) instantiating
[execution-join-ref-v1](https://github.com/giskard09/argentum-core/blob/f4d989052bb3a61691b1b156cd6dd655793fea4f/docs/spec/execution-join-ref-v1.md)
over astrogilda's real local file-write worked example
(`probityai/agent-evidence-observer`, `examples/remora_effect_bridge.py`),
as requested in
[probityai/agent-evidence-atlas#49](https://github.com/probityai/agent-evidence-atlas/issues/49#issuecomment-6072781535)
and
[#53](https://github.com/probityai/agent-evidence-atlas/issues/53).

Built and self-audited in a session on 2026-10-09. **Not yet posted anywhere.**

## Source pins (all re-verified byte-exact in this session, not assumed from memory)

| What | Pin | Verified |
|---|---|---|
| Our own spec | `giskard09/argentum-core`, `docs/spec/execution-join-ref-v1.md`, current `main` `f4d989052bb3a61691b1b156cd6dd655793fea4f` (2026-10-08) | blob hash `d75ab5f72a1824205ec6cf066bf8a790de8f6cfe` matches the file at this commit exactly — same blob astrogilda's own CASE-TABLE.md link pins |
| CASE-TABLE.md | `probityai/agent-evidence-atlas`, `examples/request-effect-join/CASE-TABLE.md`, `main` `90335fc7b9badb75f5942f942fa770cc79f780a7` | `git diff` against the `042d9ba…` commit astrogilda's own link cited — **no diff** |
| Observer source + script | `probityai/agent-evidence-observer`, `main` `04b495d823dbcc49fa47b28fe1ba359dba8d4553` | cloned fresh this session; `examples/remora_effect_bridge.py` read in full before running |
| REMORA vectors | `darklordVirtual/REMORA-research`, `conformance/autoreview-to-effect-v1/vectors.json`, commit `b25e735d36590154ff53768b4d245ad4c7996f64` | `sha256sum` against the pinned `f896178eac35aab8843f0902934f1433eb6dccb2a212fc4139a67890faaabd27` — **match** |
| Our original comment | `probityai/agent-evidence-atlas#49`, comment `6072781535`, 2026-10-09T02:06:37Z | read via `gh api`, not from memory |
| Astrogilda's follow-up | `probityai/agent-evidence-atlas#53`, 2026-10-09T06:12:52Z | read via `gh api`, not from memory |

## How the run was produced

The REMORA/Observer code is **external, untrusted-by-default code** per this
session's own sandboxing rules — running it required the creator's explicit
`!`-prefixed execution, not something this session did unilaterally. Exact
commands:

```sh
cd observer && python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python examples/remora_effect_bridge.py <run-dir> --remora-vectors <remora>/conformance/autoreview-to-effect-v1/vectors.json
.venv/bin/python examples/remora_effect_bridge.py <run-dir> --remora-vectors <remora>/conformance/autoreview-to-effect-v1/vectors.json --verify
```

Both the `run` and Observer's own `--verify` passed
(`{"status": "retained-cases-checked", ...}`) before `build_vectors.py` read
a single file out of `<run-dir>`.

## Mapping from Observer's records onto execution-join-ref-v1 (our choices, not the spec's or Observer's)

execution-join-ref-v1 leaves several things implementation-defined.
`build_vectors.py` fixes them as follows — these are OUR choices:

- `actor_id` = Observer's `request.principal_id`.
- `input_hash` = `"sha256:" + request.content_sha256`.
- `scope` = `f"{tool_id}:{target_path}"` (string concatenation of Observer's
  two separate fields — the spec gives `scope` no shape).
- `ts_ms` for the decision = Observer's `grant.issuedAt` (ISO-8601, parsed to
  epoch-ms). Observer's retained JSON has **no timestamp for the attempt or
  the terminal write** — `attempt_id`/`result_id`'s `ts_ms` use a fixed,
  declared convention (decision time +500ms / +1000ms), not evidence from
  the source. This is flagged explicitly rather than silently assumed.
- `policy_id` (decision preimage) = `f"{grant.profile}/{executionDigest}"`.
- `executor_id` = fixed literal `"probity-protected-dispatcher"`, our own
  label — Observer's records don't name the executing component.
- `canonicalization_profile_id` = `jcs-rfc8785-v1`'s resolved hash
  (`f018a628…`), per execution-join-ref-v1's own profile registry table.

## Per-case mapping and what does NOT map

| AR case | execution-join-ref-v1 outcome | Why |
|---|---|---|
| AR-00 (control) | `AUTHORIZED_EFFECTIVE_CALL` | approved == effective preimage, chain intact, no later observation |
| AR-01 (path changed) | `EFFECTIVE_CALL_REBINDING_FAILED` (invariant 6) | effective preimage differs (target_path), no second decision covers it |
| AR-02 (identity changed) | `EFFECTIVE_CALL_REBINDING_FAILED` | effective preimage differs (actor_id) |
| AR-03 (tool changed) | `EFFECTIVE_CALL_REBINDING_FAILED` | effective preimage differs (scope/tool_id). Observer's own run labels this case `UNSUPPORTED` / `unsupported-exact-vector` because it has no registered reachable alternate tool — **that labeling is about Observer's own scope, not about whether invariant 6 applies**; invariant 6 only needs the preimage to differ with no covering decision, which holds regardless |
| AR-04 (policy/context changed) | **`NOT_MODELED`** — explicitly NOT forced through invariant 6 | `approved_action_ref == effective_action_ref` under our preimage definition (principal/path/tool are unchanged); the refusal is driven by a policy/context digest that the action_ref preimage does not include at all. Treating this as `EFFECTIVE_CALL_REBINDING_FAILED` would be a real overclaim — invariant 6 is specifically about a *rewritten preimage*, not about policy freshness |
| AR-05 (file changed after success) | `POST_COMMIT_DIVERGENCE` — **proposed, not an adopted spec code** | the committed `result_id.output_hash` is preserved; a later read of the same scope recomputes a different hash. See below. |
| COVERING-DENY (synthetic) | `EFFECTIVE_CALL_REBINDING_FAILED` | a decision_id covers `effective_action_ref` and recomputes correctly, but its `outcome` is `"deny"` — see "Self-audit" finding #6 |
| COVERING-UNSUPPORTED-PROFILE (synthetic) | `UNSUPPORTED_CANONICAL_PROFILE` | a decision_id covers `effective_action_ref`, recomputes correctly, and permits it, but declares a `canonicalization_profile_id` this verifier does not implement — defensive completeness added alongside finding #6, not itself a bug |

Four additional vectors are **self-authored, not derived from any run**,
marked `"synthetic": true`, covering CASE-TABLE.md rows AR-00..AR-05 don't
exercise:

- `APPROVED-REWRITE` — a rewritten preimage that DOES obtain a second,
  independently-recomputed covering decision before dispatch. Needed
  because none of AR-00..AR-05 exercise invariant 6's pass path, only its
  failure path (see "Self-audit" below — this gap was caught for real).
- `COVERING-DENY` — same rewrite scenario as `APPROVED-REWRITE`, but the
  second decision's `outcome` is `"deny"`, not `"permit"`. Added 2026-10-10
  after babyblueviper1's mutation testing found the verifier accepted this
  as `AUTHORIZED_EFFECTIVE_CALL` — see "Self-audit" below, finding #6.
- `COVERING-UNSUPPORTED-PROFILE` — same rewrite scenario again, `outcome`
  is `"permit"` but `canonicalization_profile_id` is a profile this
  verifier does not implement. Added the same day as defensive
  completeness, not a bug fix — no run or vector had ever declared a
  different profile before this.
- `CHANGED-PREIMAGE` — a claimed `action_ref` that doesn't recompute from
  its own declared preimage → `DIGEST_MISMATCH`, the already-existing code.
  Kept deliberately distinct from `POST_COMMIT_DIVERGENCE`: this is a
  preimage-field mismatch recomputed at verification time, not a live
  external resource changing afterward.
- `MISSING-OBSERVATION` — a supported original join with no later read
  supplied. Reported `LATER_STATE_UNKNOWN`, never inferred as "unchanged".

## POST_COMMIT_DIVERGENCE — explicitly a proposal, not a spec fact

`execution-join-ref-v1` does not define this code today. Its existing
`DIGEST_MISMATCH` means "the preimage doesn't recompute from its own
fields" — it says nothing about a live external resource (here: a file)
changing after a terminal `result_id` was already committed. Reusing
`DIGEST_MISMATCH` for that would stretch its meaning. This verifier reports
`POST_COMMIT_DIVERGENCE` as a **new, proposed** failure code and never
rewrites or discards the original `result_id` when it fires — same rule
CASE-TABLE.md itself states ("Preserve the original result. Report the
later difference separately").

## Self-audit (mutation testing, run before anything else)

Per this session's own standing practice (never report a verifier green
without trying to break it), five mutations were run against `vectors.json`
before trusting the clean result:

1. Corrupted `AR-00.decision_id` → **caught** (`decision_id mismatch`).
2. Fabricated a truthy-but-unverified `covering_decision_for_effective_ref`
   on `AR-01` → **NOT caught** on the first version of `verify.py`. This was
   a real bug: the verifier accepted any non-null value as proof of a
   covering decision without recomputing it. **Fixed** — `verify.py` now
   independently recomputes that decision's own preimage and confirms it
   binds to `effective_action_ref` before accepting the pass. Re-run after
   the fix: **caught**.
3. Set `AR-05`'s observed hash to equal the committed `output_hash` without
   updating the backing `source.current_content_sha256` → **caught**
   (internal inconsistency between the observation and its own source
   field).
4. Corrupted `AR-05.result_id` → **caught** (`result_id mismatch`).
5. Re-ran the full clean `vectors.json` after the fix: **9/9 cases,
   `ALL CHECKS PASS`**.
6. **(2026-10-10, found by babyblueviper1, not by us)** Mutation testing
   against the published `f900615` found that the covering-decision check
   added for finding #2 recomputed the decision and confirmed it binds to
   `effective_action_ref`, but never read the decision's own `outcome`
   field. A covering decision recorded as `"deny"` — a rejection — still
   produced `AUTHORIZED_EFFECTIVE_CALL`, because nothing checked what the
   decision actually decided. **Fixed** — `covering_decision_verdict()` in
   `verify.py` now requires `outcome == "permit"`; anything else (`"deny"`,
   `"defer"`) returns `EFFECTIVE_CALL_REBINDING_FAILED` (reusing the
   existing code — `execution-join-ref-v1` has no code today that
   distinguishes "a decision covers this and denies it" from "no decision
   covers this at all"; see "What this does NOT establish" below). New
   vector `COVERING-DENY` added so this path has its own case, not only a
   mutation. Re-run after the fix: **10/10, `ALL CHECKS PASS`**, and
   confirmed directly that the pre-fix check logic (recompute + bind, no
   outcome read) would have returned `AUTHORIZED_EFFECTIVE_CALL` for this
   same vector's data.
7. **(2026-10-10, same pass as #6, defensive completeness — not a bug)**
   While fixing #6, `covering_decision_verdict()`'s own preimage read
   showed `canonicalization_profile_id` was likewise never checked against
   what this verifier implements (`UNSUPPORTED_CANONICAL_PROFILE` is in
   `execution-join-ref-v1`'s own taxonomy but was unused by this file).
   Unlike #6, this was never demonstrated as exploitable: no run or vector
   had declared a different profile, and this verifier has only one
   canonicalization implementation (`jcs_bytes()`, no profile dispatch), so
   a mismatched claim changed nothing about how bytes were hashed — only
   whether the claim itself was honored. Added the check and vector
   `COVERING-UNSUPPORTED-PROFILE` anyway, for the same reason #6's check
   exists: a verifier that reads a field into a hash but never acts on
   what the field says is checking the hash, not the claim. Re-run after
   adding it: **11/11, `ALL CHECKS PASS`**.

Findings #2, #6 and #7 are the ones worth being explicit about: #2 was
found and fixed before this was shown to anyone; #6 was found by an
external reader (babyblueviper1) running their own mutation testing
against the published commit, not by us, and fixed the same day it was
reported; #7 is this session's own follow-up hardening on the same field
category, not a reported bug. There is no claim here that the current
version is exhaustively adversarial-tested beyond these seven mutations —
a sixth one landing after publication is itself evidence of that.

## What this does NOT establish

- It does not run REMORA's actual transfer-funds tool or an authoritative
  ledger — same scope limit Observer's own `REMORA-EFFECT-BRIDGE.md`
  declares.
- It does not establish that `execution-join-ref-v1` itself is the right
  contract for this problem space generally — only that it maps cleanly
  onto 5 of 6 real cases plus one it was never meant to cover (AR-04).
- `POST_COMMIT_DIVERGENCE` is this verifier's proposal. It has not been
  reviewed or adopted anywhere, including internally beyond this session.
- `execution-join-ref-v1` has no failure code distinguishing "a decision
  covers the effective ref and denies it" from "no decision covers the
  effective ref at all" — both report `EFFECTIVE_CALL_REBINDING_FAILED`
  here (see "Self-audit" finding #6). The two are observably identical to
  a relying party deciding whether to trust the call, but not identical as
  evidence: one has a decision_id on record, the other has none. This gap
  is not fixed here, only reported honestly.
- The `ts_ms` convention for attempt/result (decision+500ms/+1000ms) is
  fabricated by us for lack of a source timestamp — it is NOT evidence that
  the real write happened at that offset, only a deterministic convention
  so refs are reproducible.
- **Ordering between the covering decision and the attempt: confirmed
  indeterminate, not only by us.** Beyond this verifier's own fabricated
  `ts_ms` convention (above), astrogilda confirmed
  ([probityai/agent-evidence-atlas#53](https://github.com/probityai/agent-evidence-atlas/issues/53#issuecomment-6102087790))
  that Observer's separate protected-action profile carries a signed,
  observer-attested `authorizedAt` — but that field is absent from the
  REMORA bridge inputs this verifier reads, and cannot be backfilled.
  Even where it exists, it does not resolve the question: the binding is
  signed at `seal()`, after the effect
  ([`authorization.py#L558-L567`](https://github.com/probityai/agent-evidence-observer/blob/ab93f9995afa5568e02c4d443bb06e6dd790087c/src/probity_observer/authorization.py#L558-L567)),
  which this session verified directly against the pinned commit — "the
  grant-to-claim signature is made after the write... no outside witness
  commits to the grant before the effect or independently checks the
  clock" ([`PROTECTED-ACTION-KIT.md`, Limits](https://github.com/probityai/agent-evidence-observer/blob/ab93f9995afa5568e02c4d443bb06e6dd790087c/docs/PROTECTED-ACTION-KIT.md)).
  A future case with a separately bound dispatch observation could compare
  against the covering-decision time. Until then, this verifier reports no
  ordering claim at all — not because our data is incomplete, but because
  no upstream source for it exists today.

## How to run

```sh
python3 build_vectors.py <observer-run-dir> vectors.json
python3 verify.py vectors.json
```

`build_vectors.py` requires a real `<observer-run-dir>` produced by
Observer's own `examples/remora_effect_bridge.py run ...` (see above) — it
does not fabricate the AR-00..AR-05 cases itself.
