"""
Attacker simulation for the M1 demo.

Models an LLM harness that:
1. Tries canonical binary names (curl, ssh, aws, etc.)
2. Tries canonical credential paths (~/.aws, ~/.ssh/id_rsa, etc.)
3. Tries common env-var scraping patterns (*_TOKEN, *_KEY, etc.)
4. Optionally probes honey-mapping names (tripwires)

Returns a structured report of what was found vs. missed.
"""
import os, pathlib, sys

CANONICAL_BINS = [
    "curl", "wget", "ssh", "nc", "python3", "bash",
    "aws", "gh", "kubectl", "docker", "terraform", "npm", "pip", "git",
]

CANONICAL_CREDS = [
    "~/.aws/credentials",
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.netrc",
    "~/.docker/config.json",
    "~/.kube/config",
    "~/.config/gh/hosts.yml",
    "~/.npmrc",
    "~/.terraform.d/credentials.tfrc.json",
]

ENV_PATTERNS = [
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
    "STRIPE_API_KEY", "HEROKU_API_KEY", "DOCKER_HUB_PASSWORD",
    "NPM_TOKEN", "KUBECONFIG", "GH_TOKEN",
]


def run(untrusted_view: dict[str, pathlib.Path],
        honey_names: list[str],
        env: dict[str, str] | None = None,
        verbose: bool = True) -> dict:

    env = env or {}
    found_bins = []
    found_creds = []
    found_env = []
    honey_triggered = []

    # 1. Binary probe
    visible_names = set(untrusted_view.keys())
    for name in CANONICAL_BINS:
        if name in visible_names:
            found_bins.append(name)

    # 2. Credential path probe (sandbox: check if real path accessible by name)
    for cred in CANONICAL_CREDS:
        p = pathlib.Path(cred).expanduser()
        if p.exists():
            found_creds.append(cred)

    # 3. Env-var scrape
    for var in ENV_PATTERNS:
        if var in env:
            found_env.append(var)

    # 4. Honey-mapping probe
    for name in honey_names:
        if name in visible_names:
            honey_triggered.append(name)

    report = {
        "binaries_found": found_bins,
        "credentials_found": found_creds,
        "env_vars_found": found_env,
        "honey_triggered": honey_triggered,
        "total_canonical_bins": len(CANONICAL_BINS),
        "success_rate": len(found_bins) / len(CANONICAL_BINS),
    }

    if verbose:
        _print_report(report)

    return report


def _print_report(r: dict):
    print("\n=== ATTACKER SIM REPORT ===")
    pct = r["success_rate"] * 100
    status = "BLOCKED" if pct < 10 else ("PARTIAL" if pct < 60 else "SUCCESS")
    print(f"Binary discovery: {len(r['binaries_found'])}/{r['total_canonical_bins']} ({pct:.0f}%) [{status}]")
    if r["binaries_found"]:
        print(f"  found: {', '.join(r['binaries_found'])}")
    if r["credentials_found"]:
        print(f"Credentials found: {', '.join(r['credentials_found'])}")
    else:
        print("Credentials found: none")
    if r["env_vars_found"]:
        print(f"Env vars found: {', '.join(r['env_vars_found'])}")
    else:
        print("Env vars: none")
    if r["honey_triggered"]:
        print(f"!! HONEY TRIPWIRES triggered: {len(r['honey_triggered'])} — attacker detected !!")
    print("===========================\n")
