"""
Attacker simulation: models an LLM harness probing for canonical artifacts.

Probes:
1. Canonical binary names (curl, ssh, aws, ...)
2. Canonical credential paths (~/.aws, ~/.ssh/id_rsa, ...)
3. Common env-var scraping patterns (*_TOKEN, *_KEY, ...)
4. Honey-mapping tripwires (any hit = 100% confidence hostile)

Returns a structured report; pure function, no side effects on the host.
"""
import pathlib
from dataclasses import dataclass, field

CANONICAL_BINS = [
    "curl", "wget", "ssh", "nc", "python3", "bash",
    "aws", "gh", "kubectl", "docker", "terraform", "npm", "pip", "git",
]

CANONICAL_CREDS = [
    "~/.aws/credentials", "~/.ssh/id_rsa", "~/.ssh/id_ed25519",
    "~/.netrc", "~/.docker/config.json", "~/.kube/config",
    "~/.config/gh/hosts.yml", "~/.npmrc",
    "~/.terraform.d/credentials.tfrc.json",
]

ENV_PATTERNS = [
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
    "STRIPE_API_KEY", "HEROKU_API_KEY", "NPM_TOKEN", "GH_TOKEN",
]


@dataclass
class Report:
    binaries_found: list[str] = field(default_factory=list)
    credentials_found: list[str] = field(default_factory=list)
    env_vars_found: list[str] = field(default_factory=list)
    honey_triggered: list[str] = field(default_factory=list)
    total_canonical_bins: int = 0

    @property
    def success_rate(self) -> float:
        if self.total_canonical_bins == 0:
            return 0.0
        return len(self.binaries_found) / self.total_canonical_bins

    @property
    def verdict(self) -> str:
        pct = self.success_rate * 100
        if self.honey_triggered:
            return "DETECTED"
        if pct < 10:
            return "BLOCKED"
        if pct < 60:
            return "PARTIAL"
        return "SUCCESS"


def run(visible_names: set[str],
        honey_names: list[str],
        env: dict[str, str] | None = None,
        sandbox_creds_root: pathlib.Path | None = None) -> Report:
    env = env or {}
    r = Report(total_canonical_bins=len(CANONICAL_BINS))

    for name in CANONICAL_BINS:
        if name in visible_names:
            r.binaries_found.append(name)

    for cred in CANONICAL_CREDS:
        if sandbox_creds_root is not None:
            p = sandbox_creds_root / cred.lstrip("~/")
        else:
            p = pathlib.Path(cred).expanduser()
        if p.exists():
            r.credentials_found.append(cred)

    for var in ENV_PATTERNS:
        if var in env:
            r.env_vars_found.append(var)

    honey_set = set(honey_names)
    for name in visible_names:
        if name in honey_set:
            r.honey_triggered.append(name)

    return r


def print_report(r: Report) -> None:
    print("\n=== ATTACKER SIM REPORT ===")
    pct = r.success_rate * 100
    print(f"Binary discovery: {len(r.binaries_found)}/{r.total_canonical_bins} ({pct:.0f}%) [{r.verdict}]")
    if r.binaries_found:
        print(f"  found: {', '.join(r.binaries_found)}")
    print(f"Credentials found: {', '.join(r.credentials_found) or 'none'}")
    print(f"Env vars: {', '.join(r.env_vars_found) or 'none'}")
    if r.honey_triggered:
        print(f"!! HONEY TRIPWIRES triggered: {len(r.honey_triggered)} — attacker positively identified !!")
    print("===========================\n")
