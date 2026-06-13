"""
Filesystem view simulation for M1 sandbox.

The "real" filesystem lives under sandbox/bin/ (populated with fake binaries).
trusted_view()  -> dict mapping real_name -> real_path  (pass-through)
untrusted_view() -> dict mapping scrambled_name -> real_path
"""
import pathlib

SANDBOX_BIN = pathlib.Path(__file__).parent / "bin"

# Canonical tools we track in the sandbox demo
TRACKED = [
    "curl", "ssh", "nc", "python3", "bash", "wget", "git",
    "aws", "gh", "kubectl", "docker", "terraform", "npm", "pip",
]

def trusted_view() -> dict[str, pathlib.Path]:
    return {name: SANDBOX_BIN / name for name in TRACKED if (SANDBOX_BIN / name).exists()}

def untrusted_view(mapping: dict[str, str]) -> dict[str, pathlib.Path]:
    result = {}
    for real, scrambled in mapping.items():
        p = SANDBOX_BIN / real
        if p.exists():
            result[scrambled] = p
    return result
