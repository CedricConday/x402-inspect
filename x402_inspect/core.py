"""Decode and validate x402 protocol messages (v2 spec, v1-tolerant).

x402 rides three base64-encoded JSON headers over HTTP:
  PAYMENT-REQUIRED  -> PaymentRequired      (402 response)
  PAYMENT-SIGNATURE -> PaymentPayload       (client request; v1 used X-PAYMENT)
  PAYMENT-RESPONSE  -> SettlementResponse   (settlement)

This module decodes a raw header value (base64 or plain JSON) and validates the
decoded object against the schema it looks like, returning structured findings.
Spec: https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

_EVM_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX32 = re.compile(r"^0x[0-9a-fA-F]{64}$")  # tx hash / nonce (32 bytes)
_HEX_SIG = re.compile(r"^0x[0-9a-fA-F]{130}$")  # 65-byte EVM signature
_UINT_STR = re.compile(r"^[0-9]+$")
_CAIP2 = re.compile(r"^[a-z0-9]+:[a-zA-Z0-9._-]+$")  # e.g. eip155:84532, solana:...

# Role constants payTo may use instead of a literal address (spec 5.1.2).
_PAYTO_ROLES = {"merchant"}


class Level(str, Enum):
    OK = "ok"
    WARN = "warn"
    ERROR = "error"


class Kind(str, Enum):
    PAYMENT_REQUIRED = "PaymentRequired"
    PAYMENT_PAYLOAD = "PaymentPayload"
    SETTLEMENT_RESPONSE = "SettlementResponse"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    level: Level
    path: str
    message: str


@dataclass
class Report:
    kind: Kind
    encoding: str  # "base64" | "json"
    obj: Optional[dict]
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.obj is not None and not any(f.level is Level.ERROR for f in self.findings)

    def add(self, level: Level, path: str, message: str) -> None:
        self.findings.append(Finding(level, path, message))


def decode(value: str) -> tuple[Optional[dict], str, Optional[str]]:
    """Return (obj, encoding, error). Tries base64-JSON first, then plain JSON."""
    raw = value.strip()
    if not raw:
        return None, "json", "empty input"
    # base64 (x402 headers are base64-encoded JSON)
    try:
        decoded = base64.b64decode(raw, validate=True)
        obj = json.loads(decoded)
        if isinstance(obj, dict):
            return obj, "base64", None
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass
    # plain JSON (convenience for piping a decoded body)
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj, "json", None
        return None, "json", "decoded JSON is not an object"
    except ValueError as e:
        return None, "json", f"not base64-JSON or JSON: {e}"


def classify(obj: dict) -> Kind:
    if "success" in obj and "transaction" in obj:
        return Kind.SETTLEMENT_RESPONSE
    if "payload" in obj and "accepted" in obj:
        return Kind.PAYMENT_PAYLOAD
    if "accepts" in obj:
        return Kind.PAYMENT_REQUIRED
    return Kind.UNKNOWN


def _require(r: Report, obj: dict, key: str, path: str, typ: type) -> Any:
    if key not in obj:
        r.add(Level.ERROR, f"{path}{key}", "required field missing")
        return None
    val = obj[key]
    if not isinstance(val, typ) or (typ is not bool and isinstance(val, bool)):
        r.add(Level.ERROR, f"{path}{key}", f"expected {typ.__name__}, got {type(val).__name__}")
        return None
    return val


def _check_version(r: Report, obj: dict) -> None:
    v = obj.get("x402Version")
    if v is None:
        r.add(Level.ERROR, "x402Version", "required field missing")
    elif v != 2:
        r.add(Level.WARN, "x402Version", f"expected 2 (this validator targets v2), got {v!r}")


def _check_address(r: Report, val: Any, path: str, *, allow_roles: bool = False) -> None:
    if not isinstance(val, str):
        return
    if allow_roles and val in _PAYTO_ROLES:
        return
    if not _EVM_ADDRESS.match(val):
        r.add(Level.WARN, path, "not a 0x EVM address (ok if a non-EVM network / role)")


def _check_network(r: Report, val: Any, path: str) -> None:
    if isinstance(val, str) and not _CAIP2.match(val):
        r.add(Level.WARN, path, "not CAIP-2 form (e.g. 'eip155:84532')")


def _validate_requirements(r: Report, obj: dict, path: str) -> None:
    _require(r, obj, "scheme", path, str)
    net = _require(r, obj, "network", path, str)
    if net is not None:
        _check_network(r, net, f"{path}network")
    _require(r, obj, "asset", path, str)
    if isinstance(obj.get("asset"), str):
        _check_address(r, obj["asset"], f"{path}asset")
    payto = _require(r, obj, "payTo", path, str)
    if payto is not None:
        _check_address(r, payto, f"{path}payTo", allow_roles=True)
    amount = obj.get("amount")
    if amount is not None and not (isinstance(amount, str) and _UINT_STR.match(amount)):
        r.add(Level.WARN, f"{path}amount", "should be an atomic-unit integer string, e.g. \"10000\"")


def _validate_resource(r: Report, obj: dict, path: str) -> None:
    _require(r, obj, "url", path, str)


def _validate_authorization(r: Report, obj: dict, path: str) -> None:
    for addr_key in ("from", "to"):
        v = _require(r, obj, addr_key, path, str)
        if v is not None:
            _check_address(r, v, f"{path}{addr_key}")
    val = _require(r, obj, "value", path, str)
    if val is not None and not _UINT_STR.match(val):
        r.add(Level.ERROR, f"{path}value", "must be an atomic-unit integer string")
    for ts in ("validAfter", "validBefore"):
        v = _require(r, obj, ts, path, str)
        if v is not None and not _UINT_STR.match(v):
            r.add(Level.WARN, f"{path}{ts}", "should be a unix-timestamp string")
    nonce = _require(r, obj, "nonce", path, str)
    if nonce is not None and not _HEX32.match(nonce):
        r.add(Level.WARN, f"{path}nonce", "should be a 32-byte 0x hex value")


def validate(obj: dict, kind: Kind, r: Report) -> None:
    if kind is Kind.PAYMENT_REQUIRED:
        _check_version(r, obj)
        res = _require(r, obj, "resource", "", dict)
        if isinstance(res, dict):
            _validate_resource(r, res, "resource.")
        accepts = _require(r, obj, "accepts", "", list)
        if isinstance(accepts, list):
            if not accepts:
                r.add(Level.ERROR, "accepts", "must list at least one payment requirement")
            for i, req in enumerate(accepts):
                if isinstance(req, dict):
                    _validate_requirements(r, req, f"accepts[{i}].")
                else:
                    r.add(Level.ERROR, f"accepts[{i}]", "expected object")
    elif kind is Kind.PAYMENT_PAYLOAD:
        _check_version(r, obj)
        accepted = _require(r, obj, "accepted", "", dict)
        if isinstance(accepted, dict):
            _validate_requirements(r, accepted, "accepted.")
        pl = _require(r, obj, "payload", "", dict)
        if isinstance(pl, dict):
            sig = pl.get("signature")
            if not isinstance(sig, str):
                r.add(Level.ERROR, "payload.signature", "required field missing")
            elif not _HEX_SIG.match(sig):
                r.add(Level.WARN, "payload.signature", "not a 65-byte 0x EVM signature")
            auth = pl.get("authorization")
            if isinstance(auth, dict):
                _validate_authorization(r, auth, "payload.authorization.")
            else:
                r.add(Level.ERROR, "payload.authorization", "required field missing")
    elif kind is Kind.SETTLEMENT_RESPONSE:
        _require(r, obj, "success", "", bool)
        tx = _require(r, obj, "transaction", "", str)
        if isinstance(tx, str) and not _HEX32.match(tx):
            r.add(Level.WARN, "transaction", "not a 32-byte 0x tx hash")
        _require(r, obj, "network", "", str)
        if isinstance(obj.get("payer"), str):
            _check_address(r, obj["payer"], "payer")
    else:
        r.add(Level.ERROR, "", "unrecognized message (not PaymentRequired/PaymentPayload/SettlementResponse)")


def inspect(value: str) -> Report:
    obj, encoding, err = decode(value)
    if obj is None:
        rep = Report(kind=Kind.UNKNOWN, encoding=encoding, obj=None)
        rep.add(Level.ERROR, "", err or "could not decode input")
        return rep
    kind = classify(obj)
    rep = Report(kind=kind, encoding=encoding, obj=obj)
    validate(obj, kind, rep)
    return rep
