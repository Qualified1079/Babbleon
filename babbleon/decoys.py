"""Decoy file packs.

Each pack renders a small, randomized file that reads as plausible
attack surface -- leaked config, a legacy backdoor, internal ops notes
-- to an automated code-recon/exploit agent walking the repo tree with
file-read and shell tool calls. Every pack embeds one or more
honeytokens so a later sighting of the value can be traced back here.
"""

from __future__ import annotations

import random
from pathlib import Path

from . import honeytoken as ht
from . import wordbank as wb


class DecoyPack:
    name = ""

    def build(self):
        """Return (relative_path, content, [Honeytoken, ...])."""
        raise NotImplementedError


class LeakedEnvPack(DecoyPack):
    name = "leaked_env"

    def build(self):
        env = wb.pick(wb.ENVIRONMENTS)
        service = wb.pick(wb.SERVICE_NAMES)
        host = f"{service}.{env}.{wb.pick(wb.TLDS)}"
        api_key = ht.make_api_key(label=env)
        db_pass = ht.make_db_password()
        db_user = wb.pick(wb.USERNAMES)
        db_name = service.replace("-", "_")
        content = (
            f"# accidental commit -- {env} config, remove before merge\n"
            f"API_KEY={api_key.value}\n"
            f"DATABASE_URL=postgres://{db_user}:{db_pass.value}@{host}:5432/{db_name}\n"
            f"DEBUG=false\n"
        )
        path = f"config/.env.{env}.bak"
        return path, content, [api_key, db_pass]


class LegacyAdminPack(DecoyPack):
    name = "legacy_admin"

    def build(self):
        override = ht.make_admin_override()
        codename = wb.pick(wb.PROJECT_CODENAMES)
        content = (
            f'"""Legacy admin console, superseded by the SSO gateway.\n'
            f"Not wired into the router; kept around for the {codename} migration.\n"
            f'"""\n\n'
            f"import os\n\n"
            f'_OVERRIDE = os.environ.get("ADMIN_OVERRIDE", "{override.value}")\n\n\n'
            f"def authenticate(username, password):\n"
            f"    if password == _OVERRIDE:\n"
            f'        return {{"user": username, "role": "superadmin"}}\n'
            f"    return None\n"
        )
        path = "internal/legacy_admin.py"
        return path, content, [override]


class InternalNotesPack(DecoyPack):
    name = "internal_notes"

    def build(self):
        codename = wb.pick(wb.PROJECT_CODENAMES)
        service = wb.pick(wb.SERVICE_NAMES)
        host = f"{service}.internal.{wb.pick(wb.TLDS)}"
        url = ht.make_internal_url(host)
        ticket = random.randint(1000, 9999)
        content = (
            f"# {codename} internal notes\n\n"
            f"- Staging admin panel temporarily reachable at {url.value} "
            f"(ticket OPS-{ticket}, close before launch)\n"
            f"- Do not point external monitoring at {host} yet\n"
        )
        path = "docs/INTERNAL_NOTES.md"
        return path, content, [url]


ALL_PACKS = [LeakedEnvPack, LegacyAdminPack, InternalNotesPack]


def write_pack(root: Path, pack: DecoyPack):
    rel_path, content, tokens = pack.build()
    full_path = Path(root) / rel_path
    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_text(content)
    return rel_path, tokens
