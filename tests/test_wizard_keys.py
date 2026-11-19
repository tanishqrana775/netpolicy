"""Tests for custom cross-platform key reader (wizard/keys.py)."""

from __future__ import annotations

import sys
from typing import Any

import pytest

from netpolicy.wizard.keys import _read_key_posix, flush_stdin, read_key
from netpolicy.wizard.ui import Option, RichIO


class FakeMsvcrt:
    """Mock msvcrt module providing scripted key buffer."""

    def __init__(self, chars: list[str]) -> None:
        self.queue: list[str] = list(chars)
        self.getwch_calls: int = 0

    def kbhit(self) -> bool:
        return bool(self.queue)

    def getwch(self) -> str:
        self.getwch_calls += 1
        if not self.queue:
            raise EOFError("Fake msvcrt buffer underflow")
        return self.queue.pop(0)

    def ungetwch(self, ch: str) -> None:
        self.queue.insert(0, ch)


@pytest.fixture
def fake_msvcrt_env(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Helper fixture to inject fake msvcrt and force Windows platform."""

    def _setup(chars: list[str]) -> FakeMsvcrt:
        fake = FakeMsvcrt(chars)
        monkeypatch.setitem(sys.modules, "msvcrt", fake)
        monkeypatch.setattr(sys, "platform", "win32")
        # Ensure stdin appears interactive
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("netpolicy.wizard.keys._injected_reader", None)
        return fake

    return _setup


# ==============================================================================
# Windows Keys Tests
# ==============================================================================


@pytest.mark.parametrize("prefix", ["\xe0", "\x00"])
@pytest.mark.parametrize(
    ("scan", "expected"),
    [
        ("H", "up"),
        ("P", "down"),
        ("K", "left"),
        ("M", "right"),
    ],
)
def test_windows_arrow_keys_mapping_and_consumption(
    fake_msvcrt_env: Any, prefix: str, scan: str, expected: str
) -> None:
    """Assert: ['\\xe0', scan] and ['\\x00', scan] map to arrow events consuming exactly 2 calls."""
    fake = fake_msvcrt_env([prefix, scan])
    res = read_key()
    assert res == expected
    assert fake.getwch_calls == 2
    assert not fake.kbhit()


@pytest.mark.parametrize("prefix", ["\xe0", "\x00"])
def test_windows_arrow_keys_single_event_no_stray(
    fake_msvcrt_env: Any, prefix: str
) -> None:
    """Assert each arrow returns ONE event and leaves no leftover scan codes."""
    fake = fake_msvcrt_env([prefix, "H", prefix, "P"])
    res1 = read_key()
    assert res1 == "up"
    assert fake.getwch_calls == 2

    res2 = read_key()
    assert res2 == "down"
    assert fake.getwch_calls == 4
    assert not fake.kbhit()


def test_windows_f1_and_delete_return_unknown_and_consume_two_bytes(
    fake_msvcrt_env: Any,
) -> None:
    """Assert F1 ['\\x00',';'] and Delete ['\\xe0','S'] return 'unknown' and consume both bytes."""
    # F1
    fake_f1 = fake_msvcrt_env(["\x00", ";"])
    res_f1 = read_key()
    assert res_f1 == "unknown"
    assert fake_f1.getwch_calls == 2
    assert not fake_f1.kbhit()

    # Delete
    fake_del = fake_msvcrt_env(["\xe0", "S"])
    res_del = read_key()
    assert res_del == "unknown"
    assert fake_del.getwch_calls == 2
    assert not fake_del.kbhit()


def test_windows_enter_mapping_no_drain(fake_msvcrt_env: Any) -> None:
    """Assert '\\r' -> enter with a single getwch() call and no trailing drain."""
    fake = fake_msvcrt_env(["\r", "\n"])
    res = read_key()
    assert res == "enter"
    assert fake.getwch_calls == 1


def test_windows_ctrl_c_raises_keyboard_interrupt(fake_msvcrt_env: Any) -> None:
    """Assert '\\x03' raises KeyboardInterrupt."""
    fake_msvcrt_env(["\x03"])
    with pytest.raises(KeyboardInterrupt):
        read_key()


def test_flush_stdin_is_noop_preserves_buffer(fake_msvcrt_env: Any) -> None:
    """Assert flush_stdin() is an intentional no-op that preserves buffer contents."""
    fake = fake_msvcrt_env(["\r", "\n", "x"])
    flush_stdin()
    assert fake.queue == ["\r", "\n", "x"]
    assert fake.getwch_calls == 0


# ==============================================================================
# Linux / POSIX Tests
# ==============================================================================


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX-only pty test")
def test_linux_escape_sequence_arrows_and_bare_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    """Linux branch: test arrow sequences and assert bare ESC returns without hanging."""
    import os
    import pty

    master, slave = pty.openpty()  # type: ignore[attr-defined]
    with open(slave, encoding="utf-8") as slave_f:
        monkeypatch.setattr(sys, "stdin", slave_f)

        # Test Arrow Up: \x1b[A
        os.write(master, b"\x1b[A")
        res_up = _read_key_posix()
        assert res_up == "up"

        # Test Arrow Down: \x1b[B
        os.write(master, b"\x1b[B")
        res_down = _read_key_posix()
        assert res_down == "down"

        # Test Unrecognized sequence returns unknown
        os.write(master, b"\x1b[9~")
        res_unknown = _read_key_posix()
        assert res_unknown == "unknown"

        # Test bare ESC (select timeout 0.05s, no hang)
        os.write(master, b"\x1b")
        res_esc = _read_key_posix()
        assert res_esc == "esc"

    os.close(master)


# ==============================================================================
# Menu Loop Regression Test
# ==============================================================================


def test_menu_loop_arrow_down_arrow_down_enter(fake_msvcrt_env: Any) -> None:
    """Regression: menu loop driven by fake key queue [down, down, enter] selects 3rd item."""
    from rich.console import Console

    # Key stream: Arrow Down (2 bytes), Arrow Down (2 bytes), Enter
    key_stream = ["\xe0", "P", "\xe0", "P", "\r"]
    fake_msvcrt_env(key_stream)

    console = Console(record=True, force_terminal=True, width=80)
    io = RichIO(console=console)

    options = [
        Option("1", "First choice"),
        Option("2", "Second choice"),
        Option("3", "Third choice"),
    ]

    selected = io.ask_choice("Select an option", options)
    assert selected == "3"


def test_menu_loop_ignores_unknown_prefixed_keys(fake_msvcrt_env: Any) -> None:
    """Verify that unknown keys (F1, Delete) are ignored and do not abort or select."""
    from rich.console import Console

    # Key stream: F1 (\x00;), Delete (\xe0S), Arrow Down (\xe0P), Enter (\r)
    key_stream = ["\x00", ";", "\xe0", "S", "\xe0", "P", "\r"]
    fake_msvcrt_env(key_stream)

    console = Console(record=True, force_terminal=True, width=80)
    io = RichIO(console=console)

    options = [
        Option("1", "First choice"),
        Option("2", "Second choice"),
        Option("3", "Third choice"),
    ]

    selected = io.ask_choice("Select an option", options)
    assert selected == "2"
