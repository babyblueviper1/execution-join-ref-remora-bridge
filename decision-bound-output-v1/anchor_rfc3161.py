"""Stdlib-only RFC 3161 time-stamp token reader for the decision-bound anchor
extension (see verify_decision_bound_anchor.py).

Takes a TimeStampResp (what a TSA returns, `.tsr`) or a bare
TimeStampToken and returns the TSTInfo fields the ordering rule needs:
the messageImprint (algorithm + hashed message), genTime and accuracy.

What this does NOT do: verify the TSA's CMS signature over TSTInfo or its
certificate chain. That needs X.509 and RSA/ECDSA, which the standard
library does not have. A reader who wants the full check runs, per token:

    openssl ts -verify -digest <hex> -sha256 -in token.tsr -CAfile <tsa-ca.pem> -untrusted <tsa-cert.pem>

(FreeTSA publishes cacert.pem + tsa.crt at https://freetsa.org/files/;
DigiCert's chain is in the token). Without it, a reader has checked that
the token says what the vector claims, not that the TSA signed it.

RFC 3161 section 2.4.2:
  TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime GeneralizedTime,
                         accuracy Accuracy OPTIONAL, ordering BOOLEAN DEFAULT FALSE, nonce INTEGER OPTIONAL,
                         tsa [0] GeneralName OPTIONAL, extensions [1] IMPLICIT Extensions OPTIONAL }
  Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER (1..999) OPTIONAL, micros [1] INTEGER (1..999) OPTIONAL }
"""
from __future__ import annotations

import calendar

ID_CT_TSTINFO = bytes.fromhex("060b2a864886f70d0109100104")      # OID 1.2.840.113549.1.9.16.1.4
HASH_OIDS = {"608648016503040201": "sha256", "608648016503040202": "sha384", "608648016503040203": "sha512",
             "2b0e03021a": "sha1"}


class TstError(ValueError):
    pass


def _tlv(b: bytes, i: int) -> tuple[int, bytes, int]:
    if i + 2 > len(b):
        raise TstError("truncated DER")
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7f
        if k == 0 or k > 4 or i + k > len(b):
            raise TstError("bad DER length")
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    if i + n > len(b):
        raise TstError("truncated DER")
    return tag, b[i:i + n], i + n


def _seq(body: bytes) -> list[tuple[int, bytes]]:
    out, j = [], 0
    while j < len(body):
        t, v, j = _tlv(body, j)
        out.append((t, v))
    return out


def _gen_time(s: str) -> float:
    """GeneralizedTime 'YYYYMMDDHHMMSS[.f*]Z' -> unix seconds (float)."""
    if not s.endswith("Z") or len(s) < 15:
        raise TstError(f"genTime not UTC: {s!r}")
    base, frac = s[:14], s[14:-1]
    t = calendar.timegm((int(base[0:4]), int(base[4:6]), int(base[6:8]), int(base[8:10]), int(base[10:12]), int(base[12:14])))
    if frac:
        if not frac.startswith(".") or not frac[1:].isdigit():
            raise TstError(f"bad genTime fraction: {s!r}")
        t += float("0" + frac)
    return float(t)


def read_token(raw: bytes) -> dict:
    """{hash_alg, imprint_hex, gen_time, gen_time_s, accuracy_s (None when the token states none), status (TimeStampResp only)}."""
    i = raw.find(ID_CT_TSTINFO)
    if i < 0:
        raise TstError("no TSTInfo in this token")
    _, explicit, _ = _tlv(raw, i + len(ID_CT_TSTINFO))     # [0] EXPLICIT eContent
    _, octets, _ = _tlv(explicit, 0)                        # OCTET STRING
    t, info, _ = _tlv(octets, 0)                            # TSTInfo SEQUENCE
    if t != 0x30:
        raise TstError("TSTInfo is not a SEQUENCE")
    parts = _seq(info)
    if len(parts) < 5:
        raise TstError("TSTInfo too short")
    mi = _seq(parts[2][1])
    alg = _seq(mi[0][1])[0][1].hex()
    out = {"hash_alg": HASH_OIDS.get(alg, "oid:" + alg), "imprint_hex": mi[1][1].hex()}
    gi = next((k for k, (tg, _) in enumerate(parts) if tg == 0x18), None)
    if gi is None:
        raise TstError("TSTInfo has no genTime")
    out["gen_time"] = parts[gi][1].decode("ascii")
    out["gen_time_s"] = _gen_time(out["gen_time"])
    acc = None
    if gi + 1 < len(parts) and parts[gi + 1][0] == 0x30:
        acc = 0.0
        for tg, v in _seq(parts[gi + 1][1]):
            n = int.from_bytes(v, "big") if v else 0
            acc += n if tg == 0x02 else n / 1e3 if tg == 0x80 else n / 1e6 if tg == 0x81 else 0
    out["accuracy_s"] = acc
    if raw[:1] == b"\x30":                                  # TimeStampResp: SEQUENCE { PKIStatusInfo, token }
        try:
            _, body, _ = _tlv(raw, 0)
            _, si, _ = _tlv(body, 0)
            _, st, _ = _tlv(si, 0)
            out["status"] = int.from_bytes(st, "big") if len(st) <= 2 else None
        except TstError:
            out["status"] = None
    return out
