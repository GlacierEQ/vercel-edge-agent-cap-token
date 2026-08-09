"""Edge agent CAP token — body-bound short-lived capabilities."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import Enum


def digest(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


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
        self._secret = secret

    def mint(self, path: str, body: dict, capabilities: set[str], not_after: float) -> EdgeCapToken:
        bd = digest(body)
        caps = frozenset(capabilities)
        raw = f"{path}|{bd}|{'|'.join(sorted(caps))}|{not_after}"
        mac = hmac.new(self._secret, raw.encode(), hashlib.sha256).hexdigest()
        return EdgeCapToken(path, bd, caps, not_after, mac)

    def verify(self, token: EdgeCapToken, path: str, body: dict, capability: str, now: float) -> tuple[CapStatus, str | None]:
        bd = digest(body)
        raw = f"{token.path}|{token.body_digest}|{'|'.join(sorted(token.capabilities))}|{token.not_after}"
        exp = hmac.new(self._secret, raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(exp, token.mac):
            return CapStatus.REFUSE, "BAD_MAC"
        if path != token.path:
            return CapStatus.REFUSE, "PATH_MISMATCH"
        if bd != token.body_digest:
            return CapStatus.REFUSE, "BODY_MISMATCH"
        if now > token.not_after:
            return CapStatus.REFUSE, "EXPIRED"
        if capability not in token.capabilities:
            return CapStatus.REFUSE, "CAPABILITY_NOT_GRANTED"
        return CapStatus.ALLOW, None
