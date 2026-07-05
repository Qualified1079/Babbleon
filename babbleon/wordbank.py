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


def pick(seq):
    return random.choice(seq)
