"""Decoy file packs.

Each pack renders a small, randomized file that reads as plausible
attack surface -- leaked config, a legacy backdoor, internal ops notes
-- to an automated code-recon/exploit agent walking the repo tree with
file-read and shell tool calls. Every pack embeds one or more
honeytokens so a later sighting of the value can be traced back here.
"""

from __future__ import annotations

import random
import secrets
from pathlib import Path

from . import honeytoken as ht
from . import wordbank as wb


def _join(dirname: str, filename: str) -> str:
    return filename if dirname == "." else f"{dirname}/{filename}"


class DecoyPack:
    name = ""

    def build(self, callback_base_url=None):
        """Return (relative_path, content, [Honeytoken, ...]).

        `callback_base_url`, when given, is an http(s) URL the caller
        controls; packs that embed a fetchable URL may point it there
        instead of a local placeholder so a real request from an agent
        reaches something the operator can see. Packs that don't embed
        a URL (most of them) simply ignore it.
        """
        raise NotImplementedError


class LeakedEnvPack(DecoyPack):
    name = "leaked_env"

    def build(self, callback_base_url=None):
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
        path = _join(wb.pick(wb.CONFIG_DIRS), f".env.{env}.bak")
        return path, content, [api_key, db_pass]


class LegacyAdminPack(DecoyPack):
    name = "legacy_admin"

    def build(self, callback_base_url=None):
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
        path = _join(wb.pick(wb.ADMIN_DIRS), wb.pick(wb.ADMIN_FILENAMES))
        return path, content, [override]


class InternalNotesPack(DecoyPack):
    name = "internal_notes"

    def build(self, callback_base_url=None):
        codename = wb.pick(wb.PROJECT_CODENAMES)
        service = wb.pick(wb.SERVICE_NAMES)
        tld = wb.pick([t for t in wb.TLDS if t != "internal"])
        host = f"{service}.internal.{tld}"
        url = ht.make_internal_url(host, callback_base_url=callback_base_url)
        ticket = random.randint(1000, 9999)
        content = (
            f"# {codename} internal notes\n\n"
            f"- Staging admin panel temporarily reachable at {url.value} "
            f"(ticket OPS-{ticket}, close before launch)\n"
            f"- Do not point external monitoring at {host} yet\n"
        )
        path = _join(wb.pick(wb.NOTES_DIRS), wb.pick(wb.NOTES_FILENAMES))
        return path, content, [url]


class NpmRegistryTokenPack(DecoyPack):
    name = "npm_registry_token"

    def build(self, callback_base_url=None):
        token = ht.make_registry_token("npm")
        content = (
            "# leftover from a local `npm publish --dry-run`, remove before commit\n"
            f"//registry.npmjs.org/:_authToken={token.value}\n"
            "always-auth=true\n"
        )
        path = _join(wb.pick(wb.NPM_DIRS), ".npmrc.bak")
        return path, content, [token]


class CiDeploySecretsPack(DecoyPack):
    name = "ci_deploy_secrets"

    def build(self, callback_base_url=None):
        codename = wb.pick(wb.PROJECT_CODENAMES)
        deploy_token = ht.make_registry_token("deploy")
        registry_token = ht.make_registry_token("docker")
        content = (
            f"# {codename} CI runner leftover -- do not commit real secrets here\n"
            f"DEPLOY_TOKEN={deploy_token.value}\n"
            f"DOCKER_REGISTRY_PASSWORD={registry_token.value}\n"
        )
        path = _join(wb.pick(wb.CI_DIRS), wb.pick(wb.CI_FILENAMES))
        return path, content, [deploy_token, registry_token]


ALL_PACKS = [
    LeakedEnvPack,
    LegacyAdminPack,
    InternalNotesPack,
    NpmRegistryTokenPack,
    CiDeploySecretsPack,
]


def _avoid_collision(root: Path, rel_path: str) -> str:
    """If rel_path is already taken (e.g. a repeat `seed` run landed on
    the same randomized location, or another decoy happens to collide),
    rename rather than silently overwrite -- re-seeding should scatter
    more decoys, not erase the previous ones."""
    if not (Path(root) / rel_path).exists():
        return rel_path
    p = Path(rel_path)
    return str(p.with_name(f"{p.stem}-{secrets.token_hex(2)}{p.suffix}"))


def write_pack(root: Path, pack: DecoyPack, callback_base_url=None):
    rel_path, content, tokens = pack.build(callback_base_url=callback_base_url)
    rel_path = _avoid_collision(root, rel_path)
    full_path = Path(root) / rel_path
    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_text(content)
    return rel_path, tokens
