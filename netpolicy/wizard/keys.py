"""Cross-platform raw terminal key reader for interactive wizard navigation."""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable


class KeyboardUnavailable(RuntimeError):  # noqa: N818
    """Raised when stdin is not a TTY or interactive input is unavailable."""


_injected_reader: Callable[[], str] | None = None


def set_key_reader(reader: Callable[[], str] | None) -> None:
    """Inject a custom key reader function (used for automated tests)."""
    global _injected_reader
    _injected_reader = reader


# Debug hooks recording the raw characters read
_last_raw_chars: list[str] = []
raw_history: list[str] = []


def _record_raw(ch: str) -> None:
    _last_raw_chars.append(ch)
    raw_history.append(repr(ch))


def get_last_raw_chars() -> list[str]:
    """Return the raw characters read during the most recent read_key() call."""
    return list(_last_raw_chars)


def flush_stdin() -> None:
    """No-op stub maintained for interface compatibility. No flushing allowed."""


def _decode_escape(
    read_char: Callable[[], str],
    has_more: Callable[[float], bool],
) -> str:
    """Decode VT / ANSI escape sequences starting after ESC (\x1b).

    Waits up to 50 ms for subsequent bytes:
    - If nothing follows -> 'esc'
    - If next char is '[' or 'O', reads until a final byte in '@'..'~'
      and maps A/B/C/D -> up/down/right/left, anything else -> 'unknown'.
    - If the sequence is truncated -> 'unknown', never 'esc'.
    - Any other char after ESC (Alt+key) -> 'unknown'.
    """
    if not has_more(50.0):
        return "esc"

    c1 = read_char()
    if c1 not in ("[", "O"):
        # Any other char after ESC (Alt+key) -> unknown
        return "unknown"

    seq_chars: list[str] = []
    final_byte: str | None = None
    while True:
        if not has_more(50.0):
            # Truncated escape sequence -> unknown, never esc
            return "unknown"
        b = read_char()
        if not b:
            return "unknown"
        if "@" <= b <= "~":
            final_byte = b
            break
        seq_chars.append(b)
        if len(seq_chars) > 32:
            return "unknown"

    vt_arrow_map = {
        "A": "up",
        "B": "down",
        "C": "right",
        "D": "left",
    }
    if not seq_chars and final_byte in vt_arrow_map:
        return vt_arrow_map[final_byte]
    return "unknown"


def _read_key_windows() -> str:
    """Read one logical key on Windows using msvcrt."""
    import msvcrt

    ch = msvcrt.getwch()
    _record_raw(ch)

    if ch in ("\x00", "\xe0"):
        # Blocking second read for extended key scan code
        ch2 = msvcrt.getwch()
        _record_raw(ch2)
        arrow_map = {
            "H": "up",
            "P": "down",
            "K": "left",
            "M": "right",
        }
        return arrow_map.get(ch2, "unknown")

    if ch == "\x03":
        raise KeyboardInterrupt
    if ch in ("\r", "\n"):
        return "enter"
    if ch in ("\x08", "\x7f"):
        return "backspace"

    if ch == "\x1b":

        def _has_more(timeout_ms: float) -> bool:
            if msvcrt.kbhit():
                return True
            t_end = time.monotonic() + (timeout_ms / 1000.0)
            while time.monotonic() < t_end:
                if msvcrt.kbhit():
                    return True
                time.sleep(0.002)
            return msvcrt.kbhit()

        def _read_char() -> str:
            nxt = msvcrt.getwch()
            _record_raw(nxt)
            return nxt

        return _decode_escape(_read_char, _has_more)

    if ch.isascii() and ch.isprintable():
        return ch
    return "unknown"


def _read_key_posix() -> str:
    """Read one logical key on POSIX using termios, tty, select, and os.read."""
    import select
    import termios
    import tty

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)  # type: ignore[attr-defined]
    try:
        tty.setcbreak(fd)  # type: ignore[attr-defined]

        raw = os.read(fd, 1)
        if not raw:
            return "unknown"
        ch = raw.decode("latin1")
        _record_raw(ch)

        if ch == "\x03":
            raise KeyboardInterrupt
        if ch in ("\r", "\n"):
            return "enter"
        if ch in ("\x08", "\x7f"):
            return "backspace"

        if ch == "\x1b":

            def _has_more(timeout_ms: float) -> bool:
                rlist, _, _ = select.select([fd], [], [], timeout_ms / 1000.0)
                return bool(rlist)

            def _read_char() -> str:
                b = os.read(fd, 1)
                if not b:
                    return ""
                nxt = b.decode("latin1")
                _record_raw(nxt)
                return nxt

            return _decode_escape(_read_char, _has_more)

        if ch.isascii() and ch.isprintable():
            return ch
        return "unknown"
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)  # type: ignore[attr-defined]


def read_key() -> str:
    """Read a single normalized key event from the terminal.

    Blocks until ONE logical key is available and returns one of:
    'up', 'down', 'left', 'right', 'enter', 'esc', 'backspace',
    a single printable character (e.g. '?'), or 'unknown'.

    Raises:
        KeyboardInterrupt: On Ctrl+C.
        RuntimeError: If stdin is not a TTY.
    """
    if _injected_reader is not None:
        return _injected_reader()

    if not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty():
        raise RuntimeError("Standard input is not a TTY.")

    _last_raw_chars.clear()

    if sys.platform.startswith("win"):
        return _read_key_windows()
    return _read_key_posix()


if __name__ == "__main__":
    print("Reading keys... Press 'q' or Ctrl+C to exit.")
    while True:
        try:
            k = read_key()
            raw_repr = "".join(repr(c) for c in _last_raw_chars)
            print(f"key={k} raw={raw_repr}")
            if k == "q":
                break
        except KeyboardInterrupt:
            print("\nExited via Ctrl+C")
            break
