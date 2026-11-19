"""Plain-language lint test enforcing voice rules, word limits, and banned terms."""

from __future__ import annotations

import re
from typing import Any

from netpolicy.report.humanize import STRINGS

BANNED_WORDS = [
    r"\bdns\b",
    r"\brst\b",
    r"\bicmp\b",
    r"\bsyn\b",
    r"\bttl\b",
    r"\bmiddlebox\b",
    r"\binterception\b",
    r"\bintercepted\b",
    r"\bcanary\b",
    r"\bnamespace\b",
    r"\bprobe\b",
    r"\bresolver\b",
    r"\bfirewall\b",
    r"\bcaptive portal\b",
    r"\bblocked_drop\b",
    r"\bblocked_reset\b",
    r"\bblocked_icmp\b",
    r"\bconfidence\b",
]

COMPILED_BANNED = [re.compile(pat, re.IGNORECASE) for pat in BANNED_WORDS]


def split_sentences(text: str) -> list[str]:
    """Split text into sentences while ignoring URLs and code fragments."""
    # Normalize newlines and whitespace
    text = text.replace("\r", " ").replace("\n", " ").strip()
    if not text:
        return []
    # Split on period, question mark, or exclamation mark followed by space or end
    raw_sentences = re.split(r"(?<=[.?!])\s+", text)
    cleaned = []
    for s in raw_sentences:
        s = s.strip()
        # Strip trailing punctuation
        s = re.sub(r"[.?!]+$", "", s).strip()
        if s:
            cleaned.append(s)
    return cleaned


def count_words(sentence: str) -> int:
    """Count words in a sentence."""
    tokens = [t for t in sentence.split() if t]
    return len(tokens)


def collect_default_mode_strings(data: Any, path: str = "") -> list[tuple[str, str]]:
    """Recursively collects default-mode user-facing strings from STRINGS store."""
    results: list[tuple[str, str]] = []
    # Allowed technical / verbose / command contexts excluded from default lint
    if (
        "equivalent" in path.lower()
        or "cmd" in path.lower()
        or "wsl" in path.lower()
        or "bracket" in path.lower()
        or "network_env" in path.lower()
    ):
        return results

    if isinstance(data, str):
        results.append((path, data))
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            if isinstance(item, tuple) and len(item) == 2:
                # e.g. ("1", "Option label")
                results.append((f"{path}[{item[0]}]", item[1]))
            else:
                results.extend(collect_default_mode_strings(item, f"{path}[{idx}]"))
    elif isinstance(data, dict):
        for k, v in data.items():
            results.extend(collect_default_mode_strings(v, f"{path}.{k}" if path else k))
    return results


def test_no_banned_words_in_strings_store() -> None:
    """Verify default-mode strings in STRINGS do not contain banned technical jargon."""
    collected = collect_default_mode_strings(STRINGS)
    assert len(collected) > 0

    violations = []
    for path, text in collected:
        # Check against banned words
        for pat in COMPILED_BANNED:
            match = pat.search(text)
            if match:
                violations.append(f"{path}: '{match.group(0)}' in '{text}'")

    assert not violations, "Found banned words in default UI copy:\n" + "\n".join(violations)


def test_sentence_length_in_strings_store() -> None:
    """Verify every sentence in default UI copy is 18 words or fewer."""
    collected = collect_default_mode_strings(STRINGS)
    assert len(collected) > 0

    violations = []
    for path, text in collected:
        sentences = split_sentences(text)
        for s in sentences:
            wcount = count_words(s)
            if wcount > 18:
                violations.append(f"{path}: ({wcount} words > 18) '{s}'")

    assert not violations, "Found sentences exceeding 18 words:\n" + "\n".join(violations)


def test_exact_main_menu_wording() -> None:
    """Verify main menu options match the exact specified strings."""
    opts = STRINGS["main_menu"]["options"]
    expected = [
        ("1", "Check my Wi-Fi for anything that's getting in the way"),
        (
            "2",
            "See if something I use is being blocked (email, remote login, file sharing, websites)",
        ),
        ("3", "See if my internet is being quietly redirected"),
        ("4", "Check if the network wants me to log in, or is filtering websites"),
        ("5", "Compare two earlier checks"),
        ("6", "Look at a past check"),
        ("7", "Try it in a safe practice network"),
        ("8", "Show the classic command list"),
        ("9", "Done for now"),
    ]
    assert opts == expected
