"""RFC 8785 (JCS) canonicalization helper.

Copied verbatim from giskard09/argentum-core (jcs.py, main @ time of writing)
so this verifier does not reimplement canonicalization independently of our
own published profile. Only the parts exercised by execution-join-ref-v1
preimages (ASCII string keys/values, plain integers, no floats) are used
here, but the full module is kept intact for parity with the source of
truth.
"""
import json
import math
from typing import Any


def _canonicalize(obj: Any) -> Any:
    if isinstance(obj, dict):
        sorted_keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return {k: _canonicalize(obj[k]) for k in sorted_keys}
    if isinstance(obj, list):
        return [_canonicalize(item) for item in obj]
    return obj


def _ecma_number_string(x: float) -> str:
    if math.isnan(x) or math.isinf(x):
        raise ValueError(f"JCS numbers must be finite: {x!r}")
    if x == 0.0:
        return "0"

    sign = "-" if x < 0 else ""
    text = repr(abs(x))
    mantissa, _, exp_part = text.partition("e")
    exp = int(exp_part) if exp_part else 0
    int_part, _, frac_part = mantissa.partition(".")

    raw_digits = int_part + frac_part
    stripped_leading = raw_digits.lstrip("0")
    leading_zeros = len(raw_digits) - len(stripped_leading)
    point_pos = len(int_part) - leading_zeros + exp

    digits = stripped_leading.rstrip("0") or "0"
    n = point_pos

    if digits == "0":
        return "0"
    k = len(digits)
    if 0 < n <= 21 and n >= k:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    exp_digits = digits
    exp_sign = "+" if n - 1 >= 0 else "-"
    e = abs(n - 1)
    if k == 1:
        return f"{sign}{exp_digits}e{exp_sign}{e}"
    return f"{sign}{exp_digits[0]}.{exp_digits[1:]}e{exp_sign}{e}"


def _json_default(obj: Any) -> Any:
    raise TypeError(f"Object of type {type(obj).__name__} is not JCS-serializable")


def jcs_dumps(obj: Any) -> str:
    canon = _canonicalize(obj)

    def encode(o: Any) -> str:
        if isinstance(o, bool):
            return "true" if o else "false"
        if isinstance(o, int):
            return str(o)
        if isinstance(o, float):
            return _ecma_number_string(o)
        if isinstance(o, str):
            return json.dumps(o, ensure_ascii=False)
        if o is None:
            return "null"
        if isinstance(o, dict):
            items = ",".join(f"{encode(k)}:{encode(v)}" for k, v in o.items())
            return "{" + items + "}"
        if isinstance(o, list):
            return "[" + ",".join(encode(v) for v in o) + "]"
        return _json_default(o)

    return encode(canon)


def jcs_bytes(obj: Any) -> bytes:
    return jcs_dumps(obj).encode("utf-8")
