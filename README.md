# execution-join-ref-remora-bridge

A verifier and vectors instantiating [`execution-join-ref-v1`](https://github.com/giskard09/argentum-core/blob/f4d989052bb3a61691b1b156cd6dd655793fea4f/docs/spec/execution-join-ref-v1.md)
over a real file-write worked example: `probityai/agent-evidence-observer`'s
[`REMORA-EFFECT-BRIDGE.md`](https://github.com/probityai/agent-evidence-observer/blob/main/docs/REMORA-EFFECT-BRIDGE.md),
built in response to the shared case in
[probityai/agent-evidence-atlas#49](https://github.com/probityai/agent-evidence-atlas/issues/49) /
[#53](https://github.com/probityai/agent-evidence-atlas/issues/53).

## What it checks

Six real cases (a run of Observer's own `examples/remora_effect_bridge.py`
against REMORA's pinned `autoreview-to-effect-v1` vectors) plus five
self-authored synthetic cases, each mapped onto `execution-join-ref-v1`:

| Case | Outcome |
|---|---|
| Unchanged approved write | `AUTHORIZED_EFFECTIVE_CALL` |
| Path / identity / tool changed before dispatch | `EFFECTIVE_CALL_REBINDING_FAILED` (invariant 6) |
| Policy/context digest changed | `NOT_MODELED` — explicitly not forced through invariant 6 |
| File changed after a committed successful write | `POST_COMMIT_DIVERGENCE` — **proposed new code, not part of the spec today** |
| Rewritten preimage with its own covering decision that permits it | `AUTHORIZED_EFFECTIVE_CALL` |
| Rewritten preimage with its own covering decision that denies it | `EFFECTIVE_CALL_REBINDING_FAILED` |
| Rewritten preimage with a covering decision under an unsupported canonicalization profile | `UNSUPPORTED_CANONICAL_PROFILE` |
| Claimed ref that doesn't recompute from its preimage | `DIGEST_MISMATCH` (existing code) |
| No later read supplied | `LATER_STATE_UNKNOWN` — absence is never read as "unchanged" |

Full source pins, mapping decisions, scope limits and a self-audit
(including two real bugs found and fixed — one before this was shown to
anyone, one reported by an external reader after publication) are in
[`PROVENANCE.md`](PROVENANCE.md).

## Run it

```sh
python3 build_vectors.py <observer-run-dir> vectors.json   # requires a real Observer run, see PROVENANCE.md
python3 verify.py vectors.json
```

`vectors.json` in this repo is already built from a real run; `verify.py`
re-derives every reference from the raw fields each case carries rather
than trusting the precomputed values.

## Decision-bound anchor extension (witness order)

`decision-bound-output-v1/` proves by hash dependency that a bound
`output_hash` could not exist before its decision's content did. Its docstring
names what that leaves open: a dispatcher could fabricate the decision and the
bound output together, after the fact. The anchor extension adds an
independent witness on each side:

* an OpenTimestamps proof (Bitcoin) and/or RFC 3161 tokens over the hex of
  `claimed_decision_id`, and over the hex of `recorded_output_hash`;
* a stdlib verifier (`verify_decision_bound_anchor.py`, with `anchor_ots.py`
  and `anchor_rfc3161.py`) that runs this repo's `verify_case()` first,
  unchanged, and only then orders the anchors.

| Anchor result | Meaning |
|---|---|
| `DECISION_WITNESSED_FIRST` | the decision was witnessed before the bound output, beyond the anchors' error |
| `WITNESS_ORDER_UNRESOLVED` | same block, or genTimes within accuracy (60 s each when a token states none; 7200 s for Bitcoin time across kinds) |
| `DECISION_WITNESSED_AFTER_OUTPUT` | the output was public first: a back-cited decision is not excluded |
| `WITNESS_CONFLICT` | two witnesses disagree beyond tolerance |
| `ANCHOR_PENDING` / `ANCHOR_DIGEST_MISMATCH` / `ANCHOR_INVALID` | no confirmed anchor yet / an anchor over other bytes / an anchor that does not parse or whose header is not its commitment |

It orders commitments, not writes: `KNOWN-LIMITATION-COMMITMENT-NOT-WRITE`
keeps its anchored twin, still `DECISION_WITNESSED_FIRST`. What identifies "the
same write" stays this repo's call. The tolerances are the ones ERC-8434 section
7 fixes for commitment-log anchors.

```sh
cd decision-bound-output-v1
python3 verify_decision_bound_anchor.py            # 20 synthetic cases (vectors_anchor.json) + the live cases
python3 check_anchor_mutations.py                  # 10 lax verifiers, each caught by a vector
python3 build_vectors_anchor.py                    # rebuilds the synthetic set
python3 bind_anchor_live.py                        # rebuilds the live set (network + opentimestamps-client)
```

The live cases (`vectors_anchor_live.json`, records in `anchor_live/`) carry
real Bitcoin proofs and real FreeTSA and DigiCert tokens, obtained through
`POST https://api.babyblueviper.com/work-acceptance/criteria` with
`{"sha256": "<digest hex>"}` (free). The verifier never contacts that service:
the tokens are the TSAs' own and the proofs replay to Bitcoin headers. Contributed by
[babyblueviper1 / invinoveritas](https://github.com/babyblueviper1/preaction-governance-conformance), MIT like the rest of this repo.

## License

MIT
