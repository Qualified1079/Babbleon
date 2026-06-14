"""
High-level orchestration: open vault, build mapping table, emit events.

Session is the single object the CLI and sandbox work with. Enterprise
extensions inject an EventBus with additional sinks before calling Session
methods; everything else is unchanged.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from .errors import VaultNotFound
from .events import EventBus
from .manifest import DEFAULT_TRACKED
from .mapping import Mapper, MappingTable
from .storage import ensure_dirs, vault_path
from .vault import SoftBackend, Vault, VaultPayload


@dataclass
class Session:
    """Unlocked Babbleon state: vault payload + derived mapping table."""

    payload: VaultPayload
    mapping: MappingTable
    tracked: list[str]
    bus: EventBus = field(default_factory=EventBus, compare=False, repr=False)

    @classmethod
    def initialize(cls,
                   password: str,
                   tracked: list[str] | None = None,
                   vault_file: pathlib.Path | None = None,
                   bus: EventBus | None = None) -> "Session":
        ensure_dirs()
        tracked = tracked or list(DEFAULT_TRACKED)
        path = vault_file or vault_path()
        bus = bus or EventBus()

        if path.exists():
            raise FileExistsError(f"vault already exists at {path}")

        payload = VaultPayload.new(epoch=0)
        table = Mapper(payload.host_secret).build_table(tracked, epoch=0)
        payload = payload.with_honey(table.honey_names)

        vault = Vault(SoftBackend())
        path.write_bytes(vault.seal(payload, password))
        path.chmod(0o600)
        bus.vault_sealed(epoch=0, backend="soft")

        return cls(payload=payload, mapping=table, tracked=tracked, bus=bus)

    @classmethod
    def unlock(cls,
               password: str,
               tracked: list[str] | None = None,
               vault_file: pathlib.Path | None = None,
               bus: EventBus | None = None) -> "Session":
        tracked = tracked or list(DEFAULT_TRACKED)
        path = vault_file or vault_path()
        bus = bus or EventBus()

        if not path.exists():
            raise VaultNotFound(f"no vault at {path}")

        vault = Vault(SoftBackend())
        try:
            payload = vault.unseal(path.read_bytes(), password)
        except Exception:
            bus.unlock_failed(epoch=0, backend="soft")
            raise

        table = Mapper(payload.host_secret).build_table(tracked, payload.epoch)
        return cls(payload=payload, mapping=table, tracked=tracked, bus=bus)

    def rotate(self,
               password: str,
               vault_file: pathlib.Path | None = None) -> int:
        """Bump epoch, rebuild mapping + honey, reseal. Returns new epoch."""
        path = vault_file or vault_path()
        old_epoch = self.payload.epoch
        new_epoch = old_epoch + 1

        new_table = Mapper(self.payload.host_secret).build_table(self.tracked, new_epoch)
        new_payload = (self.payload
                       .with_epoch(new_epoch)
                       .with_honey(new_table.honey_names))

        vault = Vault(SoftBackend())
        path.write_bytes(vault.seal(new_payload, password))

        self.payload = new_payload
        self.mapping = new_table
        self.bus.rotation_complete(old_epoch=old_epoch, new_epoch=new_epoch)
        return new_epoch

    def report_honey(self, triggered: list[str], process_hint: str = "") -> None:
        """Call when a honey-mapping name is probed; fires detection event."""
        self.bus.honey_triggered(
            epoch=self.payload.epoch,
            names=triggered,
            process_hint=process_hint,
        )
