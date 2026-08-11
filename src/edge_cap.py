"""Edge agent CAP token — body-bound short-lived capabilities.

The signing surface is deliberately canonical across Python and Node:
- request bodies are recursively type-tagged and key-sorted by UTF-8 bytes;
- capability/token fields are validated before use;
- the HMAC payload is a structured JSON array, not delimiter-joined text;
- expiry values are finite and encoded by their IEEE-754 binary64 bits.

Same-request replay prevention is intentionally out of scope for this reference
mechanism; callers that require single-use semantics must add a consumption
ledger above this verifier.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any

_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_PATH_LEN = 2048
_MAX_CAP_LEN = 256
_TOKEN_VERSION = "edge-cap-v1"


def _f64_hex(value: float) -> str:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("time values must be finite")
    return struct.pack(">d", value).hex()


def _validate_ascii_field(value: str, *, name: str, max_len: int) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ValueError(f"{name} must be a non-empty bounded string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be ASCII") from exc
    if any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise ValueError(f"{name} contains control characters")
    return value


def _validate_path(path: str) -> str:
    path = _validate_ascii_field(path, name="path", max_len=_MAX_PATH_LEN)
    if not path.startswith("/"):
        raise ValueError("path must be absolute")
    return path


def _validate_capability(capability: str) -> str:
    return _validate_ascii_field(capability, name="capability", max_len=_MAX_CAP_LEN)


def _normalize_capabilities(capabilities: Any) -> tuple[str, ...]:
    if isinstance(capabilities, (str, bytes)):
        raise ValueError("capabilities must be a collection")
    try:
        values = [_validate_capability(value) for value in capabilities]
    except TypeError as exc:
        raise ValueError("capabilities must be iterable") from exc
    if not values:
        raise ValueError("at least one capability is required")
    if len(values) != len(set(values)):
        raise ValueError("duplicate capabilities are not canonical")
    return tuple(sorted(values))


def _canonical_body(value: Any) -> list[Any]:
    """Return a language-stable, type-tagged JSON structure for request bodies."""
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise ValueError("integer exceeds cross-language safe range")
        return ["num", str(value)]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("body contains non-finite number")
        if value.is_integer() and abs(value) <= _MAX_SAFE_INTEGER:
            return ["num", str(int(value))]
        return ["f64", _f64_hex(value)]
    if isinstance(value, (list, tuple)):
        return ["arr", [_canonical_body(item) for item in value]]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("body object keys must be strings")
        keys = sorted(value, key=lambda key: key.encode("utf-8"))
        return ["obj", [[key, _canonical_body(value[key])] for key in keys]]
    raise ValueError(f"unsupported body value: {type(value).__name__}")


def canonical_body_bytes(obj: object) -> bytes:
    return json.dumps(
        _canonical_body(obj),
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(obj: object) -> str:
    return hashlib.sha256(canonical_body_bytes(obj)).hexdigest()


def _signing_payload(path: str, body_digest: str, capabilities: tuple[str, ...], not_after: float) -> bytes:
    payload = [_TOKEN_VERSION, path, body_digest, list(capabilities), _f64_hex(not_after)]
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _validate_secret(secret: bytes) -> bytes:
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("secret must be non-empty bytes")
    return secret


class CapStatus(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class EdgeCapToken:
    path: str
    body_digest: str
    capabilities: frozenset[str]
    not_after: float
    mac: str


class EdgeCapMint:
    def __init__(self, secret: bytes):
        self._secret = _validate_secret(secret)

    def mint(self, path: str, body: dict, capabilities: set[str], not_after: float) -> EdgeCapToken:
        path = _validate_path(path)
        caps = _normalize_capabilities(capabilities)
        not_after = float(not_after)
        _f64_hex(not_after)
        bd = digest(body)
        raw = _signing_payload(path, bd, caps, not_after)
        mac = hmac.new(self._secret, raw, hashlib.sha256).hexdigest()
        return EdgeCapToken(path, bd, frozenset(caps), not_after, mac)

    def verify(self, token: EdgeCapToken, path: str, body: dict, capability: str, now: float) -> tuple[CapStatus, str | None]:
        try:
            if not isinstance(token, EdgeCapToken):
                raise ValueError("invalid token type")
            request_path = _validate_path(path)
            request_capability = _validate_capability(capability)
            now = float(now)
            _f64_hex(now)

            token_path = _validate_path(token.path)
            token_caps = _normalize_capabilities(token.capabilities)
            token_not_after = float(token.not_after)
            _f64_hex(token_not_after)
            if not isinstance(token.body_digest, str) or len(token.body_digest) != 64:
                raise ValueError("invalid body digest")
            int(token.body_digest, 16)
            if not isinstance(token.mac, str) or len(token.mac) != 64:
                raise ValueError("invalid mac")
            int(token.mac, 16)

            bd = digest(body)
            raw = _signing_payload(token_path, token.body_digest, token_caps, token_not_after)
            exp = hmac.new(self._secret, raw, hashlib.sha256).hexdigest()
        except (TypeError, ValueError, OverflowError):
            return CapStatus.REFUSE, "MALFORMED_REQUEST_OR_TOKEN"

        if not hmac.compare_digest(exp, token.mac):
            return CapStatus.REFUSE, "BAD_MAC"
        if request_path != token_path:
            return CapStatus.REFUSE, "PATH_MISMATCH"
        if bd != token.body_digest:
            return CapStatus.REFUSE, "BODY_MISMATCH"
        if now > token_not_after:
            return CapStatus.REFUSE, "EXPIRED"
        if request_capability not in token_caps:
            return CapStatus.REFUSE, "CAPABILITY_NOT_GRANTED"
        return CapStatus.ALLOW, None
