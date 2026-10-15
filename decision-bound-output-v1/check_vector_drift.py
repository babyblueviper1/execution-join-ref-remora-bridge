"""decision-bound-output-v1: drift check between the result codes
verify_case() can actually return and the `expected_code` values declared
across vectors_decision_bound*.json, checked in both directions -- plus a
dynamic probe that a documented ordering claim actually holds in the
running code, not just in prose.

Ported from SolomonisBlack/golden-vector-provenance's `tools/check-refusal-
drift.mjs` (Apache-2.0), the pure function `evaluate(entries, throwsInCode)`
at commit 332faa5e7989fd6447e9065dbf99e721f8d15a4c, lines 44-58 -- shared
unprompted in x402-foundation/x402#2887#issuecomment-6182356482 (2026-10-15,
SolomonisBlack) after we disclosed (2026-10-11, same issue) that we only
verify vectors by hand, with no automatic check that a documented vector is
bound to a reachable point in the code, and vice versa.

WHAT PORTS UNCHANGED -- `evaluate()`'s shape: two directions checked
separately so a failure says which side is wrong (code => vectors: every
real thing the code can produce has a vector exercising it; vectors =>
code: every vector names something the code can actually produce), plus a
uniqueness check on ids, plus the discipline of two negative self-tests
proving the property itself can fail (SolomonisBlack, lines 99-102) run
against an in-memory set, never against the real files.

WHAT DOES NOT PORT, AND WHAT REPLACES IT:
- GVP's source is JS modules that `throw`; decision_bound.py's verify_case()
  is a pure Python function returning a result-code STRING, never raising.
  There is no throw-site regex here -- the "code side" of the property is
  the literal `"code": "..."` strings inside verify_case()'s own return
  statements, extracted by scanning verify_decision_bound.py's source text
  (scan_result_codes below, the direct analog of GVP's scanThrows).
- GVP's `hooks.beforeDigest` counts calls to its one expensive hash to
  prove a documented refusal never reaches it. This module's equivalent
  choke point is `bound_output_hash()`: decision_bound.py's own module
  docstring (CHECK ORDER, 2026-10-14/15 entries) claims FORGED_DECISION_
  CITATION returns before that function is ever called, and every other
  code is only reached by calling it exactly once (to compare against the
  recorded hash). count_bound_output_hash_calls below turns that claim
  from prose into a per-case assertion this script actually runs, instead
  of a fixed 0-calls check against a list of refusals -- generalized
  because most codes here are not refusals at all, they legitimately
  compute the hash once to make the comparison.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

import verify_decision_bound as vdb  # noqa: E402


def scan_result_codes(source: str) -> set[str]:
    """The code side of the property: every literal result-code string
    verify_case() returns, found by scanning its source text -- the direct
    analog of GVP's scanThrows() regex over `throw` sites."""
    return set(re.findall(r'"code":\s*"([A-Z_]+)"', source))


def discover_vectors_files() -> list[Path]:
    """Same discovery verify_decision_bound.py's own main() uses (added
    2026-10-14 after a vectors file went unchecked for 4 days under a
    single-file default) -- reused here so this check can't silently
    cover fewer files than the verifier itself does."""
    paths = sorted(HERE.glob("vectors_decision_bound*.json"))
    if not paths:
        paths = [HERE / "vectors_decision_bound.json"]
    return paths


def load_cases() -> list[dict]:
    cases = []
    for path in discover_vectors_files():
        data = json.loads(path.read_text())
        cases.extend(data["cases"])
    return cases


def evaluate(code_codes: set[str], vector_entries: list[dict]) -> list[str]:
    """Ported shape of GVP's evaluate(): code=>vectors and vectors=>code
    checked separately, plus id uniqueness. `vector_entries` are dicts with
    at least `case_id` and `expected_code` -- matching GVP's `{id, module,
    message}` shape, minus the `module` dimension (this file has exactly
    one function, no per-module scoping needed)."""
    problems = []
    vector_codes = {e["expected_code"] for e in vector_entries if e.get("expected_code")}

    for code in sorted(code_codes):
        if code not in vector_codes:
            problems.append(
                f"code => vectors: result code {code!r} is returned by verify_case() "
                "but no vector declares it as expected_code"
            )
    for code in sorted(vector_codes):
        if code not in code_codes:
            problems.append(
                f"vectors => code: expected_code {code!r} is declared by a vector but "
                "verify_case() has no return statement producing it"
            )

    ids = [e["case_id"] for e in vector_entries]
    if len(set(ids)) != len(ids):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        problems.append(f"duplicate case_id(s): {', '.join(dupes)}")

    return problems


def count_bound_output_hash_calls(case: dict) -> tuple[str, int]:
    """Dynamic probe, the replacement for GVP's beforeDigest counter: run
    verify_case() for real with bound_output_hash wrapped, and return the
    actual result code together with how many times the choke-point
    function was reached. Patches the name inside verify_decision_bound's
    own namespace (where verify_case() actually looks it up), not inside
    decision_bound -- from verify_decision_bound.py's own `from
    decision_bound import bound_output_hash, ...`, patching the origin
    module would not affect the already-bound name verify_case() calls."""
    calls = {"n": 0}
    original = vdb.bound_output_hash

    def counting(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    vdb.bound_output_hash = counting
    try:
        result = vdb.verify_case(case)
    finally:
        vdb.bound_output_hash = original
    return result["code"], calls["n"]


def check_choke_point(cases: list[dict]) -> list[str]:
    """FORGED_DECISION_CITATION must reach bound_output_hash 0 times (the
    citation check returns before it is ever built -- decision_bound.py's
    CHECK ORDER paragraph); every other code must reach it exactly once
    (every other branch computes it to compare against the recorded
    hash). A case where the actual call count disagrees with this means
    the ordering claim in the docstring no longer matches the code."""
    problems = []
    for case in cases:
        code, n_calls = count_bound_output_hash_calls(case)
        expected_n = 0 if code == "FORGED_DECISION_CITATION" else 1
        if n_calls != expected_n:
            problems.append(
                f"choke-point: case {case['case_id']!r} resolved to {code!r} but called "
                f"bound_output_hash {n_calls} time(s), expected {expected_n} -- the CHECK "
                "ORDER claim in decision_bound.py's docstring does not match the code"
            )
    return problems


def self_test() -> list[str]:
    """Negative self-tests, ported from GVP lines 99-102: the property
    must be demonstrably able to fail, checked against an in-memory set
    constructed here, never against the real files."""
    failures = []
    real_code_codes = scan_result_codes((HERE / "verify_decision_bound.py").read_text())
    real_entries = [{"case_id": c["case_id"], "expected_code": c.get("expected_code")} for c in load_cases()]

    with_extra_code = evaluate(real_code_codes | {"FABRICATED_CODE_NOBODY_DOCUMENTED"}, real_entries)
    if not (len(with_extra_code) == 1 and "code => vectors" in with_extra_code[0]):
        failures.append(
            f"negative self-test FAILED: a code added to the code side without a vector should "
            f"produce exactly one 'code => vectors' problem, got {with_extra_code!r}"
        )

    code_codes_minus_one = real_code_codes - {"BINDING_MISMATCH"}
    with_dropped_code = evaluate(code_codes_minus_one, real_entries)
    if not (len(with_dropped_code) == 1 and "vectors => code" in with_dropped_code[0] and "BINDING_MISMATCH" in with_dropped_code[0]):
        failures.append(
            f"negative self-test FAILED: removing a code from the code side while a vector still "
            f"declares it should produce exactly one 'vectors => code' problem naming it, got "
            f"{with_dropped_code!r}"
        )

    renamed_entries = [
        {**e, "expected_code": "RENAMED_CODE"} if e["expected_code"] == "BINDING_MISMATCH" else e
        for e in real_entries
    ]
    renamed_code_codes = (real_code_codes - {"BINDING_MISMATCH"}) | {"RENAMED_CODE"}
    control_renamed_both = evaluate(renamed_code_codes, renamed_entries)
    if control_renamed_both:
        failures.append(
            f"control self-test FAILED: a code renamed on BOTH sides in sync should PASS, got "
            f"{control_renamed_both!r}"
        )

    return failures


def main() -> None:
    self_test_failures = self_test()
    for f in self_test_failures:
        print(f"SELF-TEST FAIL: {f}")
    if self_test_failures:
        print("\nself-test failed -- the drift check itself cannot be trusted, not running it for real")
        sys.exit(1)
    print(f"self-test: {3 - len(self_test_failures)}/3 negative/control self-tests behave as expected")

    code_codes = scan_result_codes((HERE / "verify_decision_bound.py").read_text())
    cases = load_cases()
    vector_entries = [{"case_id": c["case_id"], "expected_code": c.get("expected_code")} for c in cases]

    problems = evaluate(code_codes, vector_entries)
    problems += check_choke_point(cases)

    print(f"\nresult codes in verify_decision_bound.py: {sorted(code_codes)}")
    print(f"expected_code values across {len(cases)} vectors: {sorted({e['expected_code'] for e in vector_entries})}")

    if problems:
        print("\nFAILURES:")
        for p in problems:
            print(f"  {p}")
        sys.exit(1)
    print(f"\nvector-drift: code and vectors agree in both directions; {len(cases)} cases, "
          "choke-point ordering holds on every case")


if __name__ == "__main__":
    main()
