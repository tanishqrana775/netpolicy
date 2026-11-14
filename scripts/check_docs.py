#!/usr/bin/env python3
"""Docs Consistency Checker for Netpolicy Documentation.

Extracts every command invoking 'netpolicy' from fenced code blocks within
documentation markdown files (such as docs/netpolicy_master_guide.md) and
verifies that:
1. The subcommand exists in the CLI's --help output.
2. Every option / flag passed to the command exists in that subcommand's --help output.

Exits with code 1 on any mismatch, or code 0 if all documented commands are valid.
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path


def get_cli_help(subcommand: str | None = None) -> str:
    """Execute python -m netpolicy [subcommand] --help and return stdout."""
    cmd = [sys.executable, "-m", "netpolicy"]
    if subcommand:
        cmd.append(subcommand)
    cmd.append("--help")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return proc.stdout


def extract_root_subcommands() -> set[str]:
    """Parse valid subcommands from netpolicy --help output."""
    help_text = get_cli_help()
    subcommands: set[str] = set()
    in_commands_section = False

    for line in help_text.splitlines():
        if "Commands" in line:
            in_commands_section = True
            continue
        if in_commands_section and (line.startswith("└") or line.startswith("+")):
            in_commands_section = False
            continue
        if in_commands_section:
            clean = line.strip().strip("│|").strip()
            # Command name in the first column followed by at least two spaces
            match = re.match(r"^([a-z0-9_-]+)\s{2,}", clean)
            if match:
                subcommands.add(match.group(1))

    return subcommands


def extract_flags_for_command(subcommand: str | None = None) -> set[str]:
    """Parse all supported flags (--option, -o) from a command's --help output."""
    help_text = get_cli_help(subcommand)
    flags: set[str] = set()
    in_options_section = False

    for line in help_text.splitlines():
        if "Options" in line:
            in_options_section = True
            continue
        if in_options_section and (line.startswith("└") or line.startswith("+")):
            in_options_section = False
            continue
        if in_options_section:
            clean = line.strip().strip("│|").strip()
            # Match options formatted as: --flag-name [ -s ] [ <type> ]
            match = re.match(r"^(--[a-zA-Z0-9-]+)(?:\s+(-[a-zA-Z0-9]))?", clean)
            if match:
                if match.group(1):
                    flags.add(match.group(1))
                if match.group(2):
                    flags.add(match.group(2))

    return flags


def extract_netpolicy_commands(file_path: Path) -> list[tuple[int, str, list[str]]]:
    """Extract netpolicy argument tokens from fenced code blocks in a markdown file.

    Returns:
        List of tuples: (line_number, full_line_str, netpolicy_args_tokens)
    """
    lines = file_path.read_text(encoding="utf-8").splitlines()
    in_code_block = False
    extracted: list[tuple[int, str, list[str]]] = []

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue

        if not in_code_block:
            continue

        if not stripped or stripped.startswith("#"):
            continue

        # Check if the line invokes netpolicy
        if "netpolicy" not in stripped:
            continue

        try:
            tokens = shlex.split(stripped, comments=True)
        except ValueError:
            tokens = stripped.split()

        if not tokens:
            continue

        # Find the netpolicy invocation token
        netpolicy_idx = -1
        non_command_prefixes = {
            "cd",
            "clone",
            "mkdir",
            "rm",
            "cat",
            "chown",
            "chmod",
            "push",
            "checkout",
        }
        for i, t in enumerate(tokens):
            if t == "-m" and i + 1 < len(tokens) and tokens[i + 1] == "netpolicy":
                netpolicy_idx = i + 1
                break
            if t == "netpolicy" or t.endswith("/netpolicy") or t.endswith("\\netpolicy"):
                prev = tokens[i - 1].lower() if i > 0 else ""
                if prev in non_command_prefixes:
                    continue
                netpolicy_idx = i
                break

        if netpolicy_idx == -1:
            continue

        args_tokens = tokens[netpolicy_idx + 1 :]
        extracted.append((idx, stripped, args_tokens))

    return extracted


def verify_documentation_commands(doc_path: Path) -> int:
    """Verifies that all netpolicy commands in doc_path use valid subcommands and flags.

    Returns:
        Number of detected errors / mismatches (0 if all passed).
    """
    print(f"=== Verifying Documentation: {doc_path} ===")
    if not doc_path.exists():
        print(f"ERROR: File not found: {doc_path}", file=sys.stderr)
        return 1

    root_subcommands = extract_root_subcommands()
    root_flags = extract_flags_for_command(None)
    print(f"Supported root subcommands: {sorted(root_subcommands)}")
    print(f"Supported root flags:       {sorted(root_flags)}")

    # Cache flags per subcommand
    subcmd_flags_cache: dict[str, set[str]] = {}
    for sc in root_subcommands:
        subcmd_flags_cache[sc] = extract_flags_for_command(sc)

    commands = extract_netpolicy_commands(doc_path)
    print(f"\nFound {len(commands)} 'netpolicy' command invocation(s) in code blocks.\n")

    errors = 0

    for lineno, line_str, args in commands:
        print(f"Line {lineno:4d}: {line_str}")

        if not args:
            print("  -> Root netpolicy invocation (no args). [OK]")
            continue

        subcommand: str | None = None
        cmd_flags: list[str] = []

        # Parse subcommand and flags
        for tok in args:
            if tok.startswith("-"):
                # Handle flag with value attached, e.g. --target=10.0.0.1
                flag_name = tok.split("=")[0]
                cmd_flags.append(flag_name)
            elif subcommand is None:
                subcommand = tok

        # 1. Verify subcommand
        if subcommand is not None and subcommand not in root_subcommands:
            print(
                f"  [ERROR] Unknown subcommand '{subcommand}' (valid: {sorted(root_subcommands)})",
                file=sys.stderr,
            )
            errors += 1
            continue

        valid_flags = subcmd_flags_cache.get(subcommand, root_flags) if subcommand else root_flags

        # 2. Verify flags
        for f in cmd_flags:
            if f not in valid_flags:
                print(
                    f"  [ERROR] Unknown flag '{f}' for command "
                    f"'{subcommand or 'root'}' (valid: {sorted(valid_flags)})",
                    file=sys.stderr,
                )
                errors += 1
            else:
                print(f"  [OK] Flag '{f}' is valid.")

    print("\n--------------------------------------------------------------------------------")
    if errors > 0:
        print(f"RESULT: FAILED ({errors} documentation inconsistency/inconsistencies found).")
        return errors
    else:
        print("RESULT: PASSED (All subcommands and options verified against CLI --help).")
        return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check documentation CLI consistency")
    parser.add_argument(
        "doc",
        nargs="?",
        type=Path,
        default=Path("docs/netpolicy_master_guide.md"),
        help="Path to markdown document to verify (default: docs/netpolicy_master_guide.md)",
    )
    args = parser.parse_args(argv)
    err_count = verify_documentation_commands(args.doc)
    return 1 if err_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
