"""Small word lists used to randomize decoy content.

Babbleon is open source, so if every deployment planted byte-identical
decoy text, an attacker who knows the tool could just grep for its
literal template strings and skip every trap. Randomizing the
codenames/hosts/usernames each time a pack is built doesn't make
decoys unfingerprintable (the *structure* of each pack is still
public), but it raises the cost above a single string match.
"""

import random

PROJECT_CODENAMES = [
    "atlasgate", "cinderveil", "duskframe", "emberline", "frostwire",
    "gravelark", "hollowreach", "ironquill", "junipercore", "kestrelbay",
    "lumenforge", "mirrorfall", "nightbarrow", "oakspire", "penumbra",
    "quartzhold", "ravenport", "silverwatch", "tidebound", "umbercliff",
]

ENVIRONMENTS = ["staging", "prod", "qa", "internal", "canary", "preprod"]

SERVICE_NAMES = [
    "auth-svc", "billing-svc", "user-svc", "gateway", "orders-svc",
    "notify-svc", "ledger-svc", "search-svc", "media-svc", "reports-svc",
]

USERNAMES = [
    "svc_deploy", "svc_migrate", "ops_admin", "svc_backup", "svc_ci",
    "svc_release", "ops_readonly", "svc_monitor",
]

TLDS = ["internal", "corp", "local-net", "svc-mesh"]

# Directory/filename variants per pack, so repeated `seed` runs land in
# different places instead of always writing the same 5 fixed paths --
# a fixed path list is itself a fingerprint an attacker who knows
# babbleon could just check directly.
CONFIG_DIRS = ["config", "conf", "deploy/config", "infra/config", "settings"]
NOTES_DIRS = ["docs", "notes", "wiki", "ops/notes"]
NOTES_FILENAMES = ["INTERNAL_NOTES.md", "OPS_NOTES.md", "runbook_notes.md", "TODO_INTERNAL.md"]
ADMIN_DIRS = ["internal", "legacy", "tools/internal", "scripts/legacy"]
ADMIN_FILENAMES = [
    "legacy_admin.py", "old_admin_panel.py", "admin_console_v1.py", "deprecated_admin.py",
]
CI_DIRS = ["ci", ".github", "deploy/ci", "build/ci"]
CI_FILENAMES = ["secrets.env.bak", "ci_secrets.env.bak", "deploy_secrets.env.bak"]
NPM_DIRS = [".", "frontend", "packages/web", "clients/js"]


def pick(seq):
    return random.choice(seq)
