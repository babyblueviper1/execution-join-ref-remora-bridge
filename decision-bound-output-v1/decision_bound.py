"""decision-bound-output-v1 -- a file-domain equivalent of EIP-3009's
nonce=decision_ref trick, answering the gap astrogilda named in
probityai/agent-evidence-atlas status.html (the first cell, citing our
execution-join-ref-v1 / REMORA bridge case #53): "ordering between the
covering decision and the call stays indeterminate".

THE GAP THIS CLOSES, PRECISELY: today (see ../build_vectors.py,
result_preimage/output_hash) a terminal write's output_hash is
"sha256:" + content_sha256 -- the hash of the bytes written, nothing else.
decision_id is never folded into it. An independent reader who only has
the final file and its output_hash cannot tell whether that output_hash
could only have been produced AFTER the covering decision existed, or
whether it is unrelated to any decision at all -- "ordering" has nothing
to attach to.

THE MECHANISM, BY ANALOGY TO EIP-3009: in a transferWithAuthorization
call, the signer picks `nonce` and sets it equal to the covering
decision's own content-addressed ref (decision_ref). The chain records
that nonce in the AuthorizationUsed event. Precedence is then provable
by HASH DEPENDENCY, not by comparing clocks: nonce is a value the signer
could not have produced without already knowing decision_ref, and
decision_ref is itself a one-way hash of the decision's own fields -- so
a valid authorization carrying that nonce could not have been
constructed before the decision existed.

Applied to a file write: instead of hashing the written content alone,
the dispatcher folds the covering decision's own decision_id into the
output commitment:

    output_hash = SHA-256(JCS({content_sha256, decision_id, version}))

decision_id is itself SHA-256(JCS(decision_preimage)) (same convention
already used everywhere else in this repo, see ../verify.py's `ref()`).
Because decision_id is a one-way hash of the decision's own fields
(decision_preimage has FIVE: action_ref, canonicalization_profile_id,
outcome, policy_id, ts_ms -- all five are hashed, see
docs/spec/execution-join-ref-v1.md in argentum-core and
../verify.py:decision_pre for the exact shape), it is not a value
the dispatcher could pick in advance or guess; producing an output_hash
that recomputes against a specific decision_id is only possible once
that decision's full content already existed. An independent verifier
-- someone who never watched the write happen, who has only: the final
content (or its hash), the claimed decision_id, the decision's own
preimage fields (from wherever that decision is logged/anchored
separately), and the recorded output_hash -- can confirm this
dependency by recomputation alone. No clock is trusted anywhere in this
check.

A citation is only accepted if, in addition to recomputing, the cited
decision's own `outcome` field is `"permit"`: a decision that is
structurally bound to the output but recorded `"deny"` or `"defer"`
authorized nothing, even though the hash dependency itself is sound
(same lesson already applied to execution-join-ref-v1's own
covering_decision_verdict() in ../verify.py, PROVENANCE.md finding #6).
This is part of the contract, not an implementation detail left for the
verifier to invent on its own -- see verify_case() in
verify_decision_bound.py, which returns UNAUTHORIZED_BINDING for exactly
this case.

WHAT THIS DOES NOT ESTABLISH (same discipline as PROVENANCE.md elsewhere
in this repo -- declaring limits is part of the artifact, not an
afterthought):

- It does not prove WHEN the decision was made in wall-clock time, only
  that the output could not exist without the decision's content
  already existing. "Before" here means "logically / causally prior",
  not "at an earlier timestamp" -- the same thing EIP-3009's nonce trick
  actually proves; the chain's own block time is a SEPARATE, additional
  fact bolted on afterward (the "AuthorizationUsed" event timestamp),
  not part of the hash-dependency argument itself.
- It does not prevent the dispatcher from fabricating BOTH the decision
  and the bound output at the same time, after the fact, with no real
  gap between them -- it proves dependency, not elapsed time. A durable,
  independently-witnessed publication of decision_id BEFORE the bound
  output_hash is published (e.g. anchoring decision_id on a public
  ledger, same pattern as this org's other *-action-ref-anchor repos)
  would add a true timestamp the dispatcher cannot have influenced --
  that is a genuine strengthening, not required for the dependency proof
  itself, and not built here. Flagged as an open extension.
- It says nothing about whether decision_id is used ONCE or re-used
  across several different writes. Re-use may or may not be meaningful
  depending on what the decision actually authorizes (unlike an
  EIP-3009 payment authorization, where nonce reuse would double-spend
  the same value, a single decision authorizing several writes may be
  intentional). If single-use matters for a given decision scope, a
  replay guard analogous to delegation-chain-ref-v1's SeenRegistry
  (already used elsewhere in this org's code) is the natural fit -- not
  designed or built here, flagged as an open question, not solved
  silently.
- It requires the decision's own preimage fields to be available to the
  verifier from SOME separate channel (a policy log, an anchor, a
  manifest the decision engine itself published) -- this mechanism only
  defines how the WRITE binds to a decision_id, not how a verifier comes
  to trust that the cited decision record is the complete, unaltered one.
  That is the same chain-of-custody question execution-join-ref-v1's own
  decision_preimage already has, unchanged here.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from jcs import jcs_bytes  # noqa: E402

VERSION = "decision-bound-output-v1"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ref(preimage: dict) -> str:
    return "sha256:" + sha256_hex(jcs_bytes(preimage))


def decision_id_from_preimage(decision_preimage: dict) -> str:
    """Same convention as execution-join-ref-v1's decision_id elsewhere in
    this repo: SHA-256(JCS(decision_preimage))."""
    return ref(decision_preimage)


def bound_output_preimage(content_sha256: str, decision_id: str) -> dict:
    """Prefix convention, declared explicitly (not obvious from reading the
    dict literal alone): `content_sha256` is BARE hex, no `sha256:` prefix
    -- the same convention execution-join-ref-v1's own request.content_sha256
    uses elsewhere in this repo. `decision_id` already carries the
    `sha256:` prefix, because it comes out of `ref()` (decision_id_from_
    preimage), which adds it. Pass each argument exactly as its own
    producer gives it -- do not strip or add prefixes here.

    `version` is this module's own constant (`VERSION`, "decision-bound-
    output-v1") -- it identifies the PREIMAGE SHAPE, and is unrelated to
    any file-level `"profile"` label a vectors JSON might carry (e.g.
    vectors_decision_bound_real_run.json's top-level "profile":
    "decision-bound-output-v1-real-run", or build_vectors.py's
    "execution-join-ref-v1-remora-bridge-v0" elsewhere in this repo) --
    those are human-readable labels for a FILE, never hashed, never part
    of this or any other preimage here.
    """
    return {
        "content_sha256": content_sha256,
        "decision_id": decision_id,
        "version": VERSION,
    }


def bound_output_hash(content_sha256: str, decision_id: str) -> str:
    """The new output_hash: a commitment to the written content AND the
    covering decision together, instead of the content alone. See
    bound_output_preimage's docstring for the exact prefix convention
    each argument must already carry."""
    return ref(bound_output_preimage(content_sha256, decision_id))


def legacy_output_hash(content_sha256: str) -> str:
    """Today's shape (../build_vectors.py: output_hash = "sha256:" +
    content_sha256) -- carries no decision binding at all. Used here only
    to recognize the unverifiable-but-not-tampered case."""
    return "sha256:" + content_sha256
