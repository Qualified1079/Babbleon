"""
TPM2 vault backend: host_secret sealed to PCR measurements.

Seals against PCRs 4 (boot manager code), 8 (kernel cmdline),
9 (initrd) in ADDITION to PCR7 (Secure Boot). PCR7-only sealing
is bypassable via custom initrd with manipulated PCR7 (oddlama technique).

Requires: tpm2-tools in PATH, tpm2-tss library.

REVIEW(manual): authorized policies for post-kernel-update re-seal are
not yet implemented. Current flow requires manual re-seal after kernel
updates. See tpm2-tools `tpm2_policyauthorize` docs for the pattern.

REVIEW(manual): this module executes tpm2_* subprocesses. On real
hardware, test with tpm2-abrmd daemon vs direct /dev/tpm0 access;
resource manager behavior differs between distros.
"""
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

from ..errors import HardwareUnavailable, VaultError

# PCRs that must be included in the seal policy; do NOT drop 8/9.
_SEAL_PCRS = "4,7,8,9"
_CONTEXT_FILE = pathlib.Path("~/.config/babbleon/tpm-context.ctx").expanduser()


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, check=True, capture_output=True, **kwargs)
    except FileNotFoundError:
        raise HardwareUnavailable("tpm2-tools not found in PATH")
    except subprocess.CalledProcessError as exc:
        raise VaultError(f"tpm2 command failed: {exc.stderr.decode(errors='replace')}") from exc


class TPMBackend:
    """
    KEK backend: key sealed to TPM2 PCR policy.

    derive_age_passphrase() is called at unlock time; it unseals the
    KEK from the TPM and returns it as the age passphrase.

    The sealed blob (context file) is stored at _CONTEXT_FILE.
    On a fresh machine, call TPMBackend.enroll(kek_bytes) once.
    """

    def __init__(self, context_path: pathlib.Path | None = None) -> None:
        self.context_path = context_path or _CONTEXT_FILE

    @classmethod
    def available(cls) -> bool:
        try:
            subprocess.run(["tpm2_getcap", "properties-fixed"], check=True,
                           capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def enroll(self, kek_bytes: bytes) -> None:
        """Seal kek_bytes to current PCR values. Run after each kernel update."""
        self.context_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(kek_bytes)
            tmp = f.name
        try:
            _run([
                "tpm2_create", "-C", "e",
                "-i", tmp,
                "-u", str(self.context_path) + ".pub",
                "-r", str(self.context_path) + ".priv",
                "-L", f"pcr:{_SEAL_PCRS}",
            ])
        finally:
            os.unlink(tmp)

    def _unseal(self) -> bytes:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".out") as f:
            out_path = f.name
        try:
            _run([
                "tpm2_unseal",
                "-u", str(self.context_path) + ".pub",
                "-r", str(self.context_path) + ".priv",
                "-L", f"pcr:{_SEAL_PCRS}",
                "-o", out_path,
            ])
            return pathlib.Path(out_path).read_bytes()
        finally:
            if pathlib.Path(out_path).exists():
                os.unlink(out_path)

    def derive_age_passphrase(self, _credential=None) -> str:
        kek_bytes = self._unseal()
        return hashlib.sha256(kek_bytes + b"babbleon-tpm-age-v1").hexdigest()
