"""Decoy file packs.

Each pack renders a small, randomized file that reads as plausible
attack surface -- leaked config, a legacy backdoor, internal ops notes
-- to an automated code-recon/exploit agent walking the repo tree with
file-read and shell tool calls. Every pack embeds one or more
honeytokens so a later sighting of the value can be traced back here.
"""

from __future__ import annotations

import itertools
import os
import random
import secrets
from pathlib import Path

from . import honeytoken as ht
from . import wordbank as wb
from .errors import BabbleonError


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


_MAX_COLLISION_ATTEMPTS = 1000


def _candidate_paths(rel_path: str):
    """The original path first, then an unbounded stream of randomized
    fallbacks -- tried in order until one doesn't already exist."""
    yield rel_path
    p = Path(rel_path)
    while True:
        yield str(p.with_name(f"{p.stem}-{secrets.token_hex(2)}{p.suffix}"))


def write_pack(root: Path, pack: DecoyPack, callback_base_url=None):
    """Write a pack's rendered content to disk under `root`.

    If the chosen path is already taken (e.g. a repeat `seed` run landed
    on the same randomized location), try renamed fallbacks instead of
    overwriting -- re-seeding should scatter more decoys, not erase the
    previous ones. Uses O_CREAT|O_EXCL so the "does it exist" check and
    the write are atomic -- no window for a second concurrent `seed` to
    land on the same path in between.
    """
    rel_path, content, tokens = pack.build(callback_base_url=callback_base_url)
    root = Path(root)
    encoded = content.encode()
    attempts = itertools.islice(_candidate_paths(rel_path), _MAX_COLLISION_ATTEMPTS)
    for candidate in attempts:
        full_path = root / candidate
        full_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(full_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as f:
            f.write(encoded)
        return candidate, tokens
    raise BabbleonError(
        f"could not find a free path for decoy after {_MAX_COLLISION_ATTEMPTS} attempts: {rel_path}"
    )
