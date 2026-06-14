"""
FIDO2 hmac-secret vault backend: hardware token + physical tap.

Uses CTAP2 hmac-secret extension via libfido2 (python-fido2).
Salt is stored on disk; HMAC-SHA-256(credential_secret, salt) gives
the KEK. The credential_secret never leaves the token.

REVIEW(manual): credential enrollment UX (PIN, attestation handling)
needs work; this module ships the unlock path. Enrollment requires
user-driven CLI flow with PIN entry and explicit consent ceremony.

REVIEW(manual): test against multiple authenticators (YubiKey 5,
Solokey, OnlyKey) — hmac-secret extension support varies.
"""
import hashlib
import os
import pathlib

from ..errors import HardwareUnavailable, VaultError

_SALT_PATH = pathlib.Path("~/.config/babbleon/fido2-salt").expanduser()


class FIDO2Backend:
    """
    KEK backend: FIDO2 hmac-secret derived key.

    Requires python-fido2 (`pip install fido2`). If not installed,
    raises HardwareUnavailable at unlock time, NOT import time —
    keeps the module loadable in test/CI without the dep.
    """

    def __init__(self,
                 credential_id: bytes,
                 salt_path: pathlib.Path | None = None,
                 rp_id: str = "babbleon.local") -> None:
        self.credential_id = credential_id
        self.salt_path = salt_path or _SALT_PATH
        self.rp_id = rp_id

    @classmethod
    def generate_salt(cls, path: pathlib.Path | None = None) -> bytes:
        p = path or _SALT_PATH
        p.parent.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(32)
        p.write_bytes(salt)
        p.chmod(0o600)
        return salt

    def _import_fido2(self):
        try:
            from fido2.client import Fido2Client
            from fido2.hid import CtapHidDevice
            return Fido2Client, CtapHidDevice
        except ImportError as exc:
            raise HardwareUnavailable(
                "python-fido2 not installed; install with `pip install fido2`"
            ) from exc

    def _get_hmac_output(self, salt: bytes) -> bytes:
        Fido2Client, CtapHidDevice = self._import_fido2()
        devs = list(CtapHidDevice.list_devices())
        if not devs:
            raise HardwareUnavailable("no FIDO2 authenticator present")

        # REVIEW(manual): wire up the actual get_assertion call with the
        # hmac-secret extension. python-fido2 API: client.get_assertion(
        #   PublicKeyCredentialRequestOptions(..., extensions={"hmacGetSecret": {"salt1": salt}})
        # ).get_response(0). Skeleton only here; full implementation needs
        # PIN handling, user-presence prompt, and origin/rp_id wiring.
        raise NotImplementedError(
            "FIDO2 backend assertion flow stubbed; see REVIEW comment"
        )

    def derive_age_passphrase(self, _credential=None) -> str:
        if not self.salt_path.exists():
            raise VaultError(f"FIDO2 salt missing: {self.salt_path}")
        salt = self.salt_path.read_bytes()
        hmac_out = self._get_hmac_output(salt)
        return hashlib.sha256(hmac_out + b"babbleon-fido2-age-v1").hexdigest()
