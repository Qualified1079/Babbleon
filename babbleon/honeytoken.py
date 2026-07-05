"""Fake-but-plausible secrets ("honeytokens") planted inside decoy files.

Formats deliberately avoid mimicking real cloud-provider secret shapes
(e.g. AWS's `AKIA...` access-key prefix) so a planted token doesn't trip
GitHub's secret-scanning partner program and get auto-forwarded to a real
provider as a false report. The goal is to read as *a* credential to a
naive grep or an LLM agent skimming the tree, not to pass a specific
vendor's format validator.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import asdict, dataclass, field

TOKEN_MARK = "bbln"


def _hex(n):
    return secrets.token_hex(n)


def _urlsafe(n):
    return secrets.token_urlsafe(n)


def _new_id():
    return secrets.token_hex(8)


@dataclass
class Honeytoken:
    id: str
    kind: str
    value: str
    created_at: float = field(default_factory=time.time)
    live: bool = False

    def to_dict(self):
        return asdict(self)


def make_api_key(label: str = "live") -> Honeytoken:
    token_id = _new_id()
    value = f"{TOKEN_MARK}_{label}_{token_id}{_hex(10)}"
    return Honeytoken(id=token_id, kind="api_key", value=value)


def make_db_password() -> Honeytoken:
    token_id = _new_id()
    value = f"{token_id}{_urlsafe(9)}"
    return Honeytoken(id=token_id, kind="db_password", value=value)


def make_admin_override() -> Honeytoken:
    token_id = _new_id()
    value = f"{TOKEN_MARK}-override-{token_id}"
    return Honeytoken(id=token_id, kind="admin_override", value=value)


def make_internal_url(host: str, callback_base_url: str | None = None) -> Honeytoken:
    """A fake internal-service URL planted in decoy text.

    By default this is a purely local placeholder -- nothing is ever
    fetched, it's just text an agent might read. If `callback_base_url`
    is supplied (an http(s) URL the caller controls, e.g. their own
    webhook receiver or a canary-token service), the honeytoken instead
    points *there*, with the fake host/id folded into the path, so a
    real HTTP request from an agent actually reaches something the
    operator can see. This never happens unless the caller explicitly
    passes a URL -- babbleon makes no network calls of its own.
    """
    token_id = _new_id()
    if callback_base_url:
        value = f"{callback_base_url.rstrip('/')}/babbleon/{host}/{token_id}"
        return Honeytoken(id=token_id, kind="internal_url", value=value, live=True)
    value = f"https://{host}/api/v1/internal/{token_id}"
    return Honeytoken(id=token_id, kind="internal_url", value=value)
