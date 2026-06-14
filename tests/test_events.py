"""EventBus: emit, add_sink, named helpers, sink isolation on failure."""
from babbleon.events import EventBus, EventSink


class CapturingSink:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(self, event: dict) -> None:
        self.events.append(event)


class FailingSink:
    def emit(self, event: dict) -> None:
        raise RuntimeError("intentional sink failure")


def test_emit_to_default_sink():
    bus = EventBus(default_sink=CapturingSink())
    bus.emit({"event": "test", "epoch": 0})
    # default sink captured it; verify by replacing & checking
    cap = CapturingSink()
    bus = EventBus(default_sink=cap)
    bus.emit({"event": "x"})
    assert cap.events == [{"event": "x"}]


def test_add_sink_fanout():
    a, b = CapturingSink(), CapturingSink()
    bus = EventBus(default_sink=a)
    bus.add_sink(b)
    bus.emit({"event": "fanout"})
    assert a.events == b.events == [{"event": "fanout"}]


def test_failing_sink_does_not_break_others():
    cap = CapturingSink()
    bus = EventBus(default_sink=FailingSink())
    bus.add_sink(cap)
    bus.emit({"event": "should-arrive"})
    assert cap.events == [{"event": "should-arrive"}]


def test_named_helpers():
    cap = CapturingSink()
    bus = EventBus(default_sink=cap)
    bus.honey_triggered(epoch=3, names=["foo"], process_hint="pid=1234")
    bus.rotation_complete(old_epoch=2, new_epoch=3)
    bus.unlock_failed(epoch=2, backend="soft")
    bus.vault_sealed(epoch=3, backend="soft")
    events = [e["event"] for e in cap.events]
    assert events == ["honey_triggered", "rotation_complete", "unlock_failed", "vault_sealed"]
    assert cap.events[0]["severity"] == "critical"
    assert cap.events[1]["new_epoch"] == 3


def test_sink_protocol_structurally_satisfied():
    # CapturingSink has the right shape; Protocol satisfaction is structural.
    assert hasattr(CapturingSink, "emit")
    assert callable(CapturingSink.emit)
