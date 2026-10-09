# execution-join-ref-remora-bridge

A verifier and vectors instantiating [`execution-join-ref-v1`](https://github.com/giskard09/argentum-core/blob/f4d989052bb3a61691b1b156cd6dd655793fea4f/docs/spec/execution-join-ref-v1.md)
over a real file-write worked example: `probityai/agent-evidence-observer`'s
[`REMORA-EFFECT-BRIDGE.md`](https://github.com/probityai/agent-evidence-observer/blob/main/docs/REMORA-EFFECT-BRIDGE.md),
built in response to the shared case in
[probityai/agent-evidence-atlas#49](https://github.com/probityai/agent-evidence-atlas/issues/49) /
[#53](https://github.com/probityai/agent-evidence-atlas/issues/53).

## What it checks

Six real cases (a run of Observer's own `examples/remora_effect_bridge.py`
against REMORA's pinned `autoreview-to-effect-v1` vectors) plus three
self-authored synthetic cases, each mapped onto `execution-join-ref-v1`:

| Case | Outcome |
|---|---|
| Unchanged approved write | `AUTHORIZED_EFFECTIVE_CALL` |
| Path / identity / tool changed before dispatch | `EFFECTIVE_CALL_REBINDING_FAILED` (invariant 6) |
| Policy/context digest changed | `NOT_MODELED` — explicitly not forced through invariant 6 |
| File changed after a committed successful write | `POST_COMMIT_DIVERGENCE` — **proposed new code, not part of the spec today** |
| Rewritten preimage with its own covering decision | `AUTHORIZED_EFFECTIVE_CALL` |
| Claimed ref that doesn't recompute from its preimage | `DIGEST_MISMATCH` (existing code) |
| No later read supplied | `LATER_STATE_UNKNOWN` — absence is never read as "unchanged" |

Full source pins, mapping decisions, scope limits and a self-audit
(including one real bug found and fixed before this was shown to anyone)
are in [`PROVENANCE.md`](PROVENANCE.md).

## Run it

```sh
python3 build_vectors.py <observer-run-dir> vectors.json   # requires a real Observer run, see PROVENANCE.md
python3 verify.py vectors.json
```

`vectors.json` in this repo is already built from a real run; `verify.py`
re-derives every reference from the raw fields each case carries rather
than trusting the precomputed values.

## License

MIT
