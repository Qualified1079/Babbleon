"""
Detection and audit event bus.

The public package emits events; sinks consume them. The default sink
prints to stderr. Enterprise sinks (SIEM forwarder, central escrow alert,
webhook) are registered via the babbleon.event_sinks entry_point group.

Event types are intentionally simple dicts so they cross package boundaries
without import coupling. Each event has at minimum:
  {"event": str, "epoch": int, ...extra fields}
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Protocol

log = logging.getLogger(__name__)


class EventSink(Protocol):
    """Protocol that enterprise event sinks must satisfy."""
    def emit(self, event: dict[str, Any]) -> None: ...


class StderrSink:
    """Default sink: log to stderr. Replace in enterprise with a SIEM forwarder."""
    def emit(self, event: dict[str, Any]) -> None:
        print(f"[babbleon] {event}", file=sys.stderr)


class EventBus:
    """
    Thin multiplexer: emit an event to all registered sinks.

    Enterprise package registers additional sinks at startup:
        bus.add_sink(SIEMForwarder(...))
        bus.add_sink(EscrowAlertSink(...))
    """

    def __init__(self, default_sink: EventSink | None = None) -> None:
        self._sinks: list[EventSink] = [default_sink or StderrSink()]

    def add_sink(self, sink: EventSink) -> None:
        self._sinks.append(sink)

    def emit(self, event: dict[str, Any]) -> None:
        for sink in self._sinks:
            try:
                sink.emit(event)
            except Exception as exc:
                log.warning("event sink %s failed: %s", sink, exc)

    # -- named event helpers --------------------------------------------------

    def honey_triggered(self, *, epoch: int, names: list[str], process_hint: str = "") -> None:
        self.emit({
            "event": "honey_triggered",
            "epoch": epoch,
            "names": names,
            "process_hint": process_hint,
            "severity": "critical",
        })

    def unlock_failed(self, *, epoch: int, backend: str) -> None:
        self.emit({
            "event": "unlock_failed",
            "epoch": epoch,
            "backend": backend,
            "severity": "warning",
        })

    def rotation_complete(self, *, old_epoch: int, new_epoch: int) -> None:
        self.emit({
            "event": "rotation_complete",
            "old_epoch": old_epoch,
            "new_epoch": new_epoch,
            "severity": "info",
        })

    def vault_sealed(self, *, epoch: int, backend: str) -> None:
        self.emit({
            "event": "vault_sealed",
            "epoch": epoch,
            "backend": backend,
            "severity": "info",
        })
