"""Static safety linter and test suite for netpolicy lab scripts.

Enforces non-negotiable safety rules for lab scripts:
- Prohibits any execution of iptables, nft, ip route, ip addr, ip link set,
  sysctl, or tc in the host network namespace.
- Mandates all network mutations occur via nsx() helper or "ip netns exec np-".
- Requires veth pairs to have BOTH endpoints placed directly into np-* namespaces.
- Strictly forbids any invocation of sudo.
"""

from __future__ import annotations

import ast
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

FORBIDDEN_HOST_COMMANDS = {
    "iptables",
    "iptables-legacy",
    "iptables-nft",
    "ip6tables",
    "nft",
    "sysctl",
    "tc",
}

FORBIDDEN_IP_SUBCOMMANDS = {
    "route",
    "addr",
    "address",
    "link",
}

COMMAND_DELIMITERS = {"&&", "||", ";", "|", "&"}


@dataclass(frozen=True)
class SafetyViolation:
    """Represents a detected safety violation in a lab script."""

    filename: str
    lineno: int
    command: str
    message: str

    def __str__(self) -> str:
        return f"{self.filename}:{self.lineno}: {self.message} -> '{self.command}'"


class LabSafetyLinter:
    """Static safety linter for lab shell and Python files."""

    def __init__(self) -> None:
        self.violations: list[SafetyViolation] = []

    def clear(self) -> None:
        self.violations.clear()

    # ------------------------------------------------------------------
    # Shell Script Linting
    # ------------------------------------------------------------------

    def lint_shell_code(self, code: str, filename: str = "<string>") -> list[SafetyViolation]:
        """Lint raw shell script content and return any safety violations."""
        violations: list[SafetyViolation] = []
        raw_lines = code.splitlines()
        joined_lines = self._join_continuations(raw_lines)

        in_heredoc = False
        heredoc_delim = ""

        for lineno, line in joined_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if in_heredoc:
                if (
                    stripped == heredoc_delim
                    or stripped == f"'{heredoc_delim}'"
                    or stripped == f'"{heredoc_delim}"'
                ):
                    in_heredoc = False
                    heredoc_delim = ""
                continue

            heredoc_match = re.search(r"<<-?\s*['\"]?([A-Za-z0-9_]+)['\"]?", line)
            if heredoc_match:
                in_heredoc = True
                heredoc_delim = heredoc_match.group(1)

            # Extract any command substitutions $(...) or `...` and check them first
            sub_commands = self._extract_subshells(stripped)
            for sub_cmd in sub_commands:
                sub_violations = self._lint_shell_line(sub_cmd, lineno, filename)
                violations.extend(sub_violations)

            # Replace command substitutions with placeholder to avoid parsing errors
            clean_line = re.sub(r"\$\([^\)]*\)", "SUBSHELL_PLACEHOLDER", stripped)
            clean_line = re.sub(r"`[^`]*`", "SUBSHELL_PLACEHOLDER", clean_line)

            line_violations = self._lint_shell_line(clean_line, lineno, filename)
            violations.extend(line_violations)

        return violations

    def _join_continuations(self, lines: Sequence[str]) -> list[tuple[int, str]]:
        joined: list[tuple[int, str]] = []
        current = ""
        start_line = 1
        for idx, line in enumerate(lines, 1):
            rstripped = line.rstrip("\r\n")
            if rstripped.endswith("\\"):
                if not current:
                    start_line = idx
                current += rstripped[:-1] + " "
            else:
                if current:
                    joined.append((start_line, current + rstripped))
                    current = ""
                else:
                    joined.append((idx, rstripped))
        if current:
            joined.append((start_line, current))
        return joined

    def _extract_subshells(self, line: str) -> list[str]:
        subshells: list[str] = []
        for match in re.finditer(r"\$\((.*?)\)", line):
            subshells.append(match.group(1).strip())
        for match in re.finditer(r"`(.*?)`", line):
            subshells.append(match.group(1).strip())
        return [s for s in subshells if s]

    def _lint_shell_line(self, line: str, lineno: int, filename: str) -> list[SafetyViolation]:
        violations: list[SafetyViolation] = []
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError:
            # Fallback to simple split on malformed shell quotes
            tokens = line.split()

        if not tokens:
            return violations

        # Split token stream on command separators (;, &&, ||, |, &)
        command_groups = self._split_command_tokens(tokens)

        for cmd_tokens in command_groups:
            cmd_violation = self._check_command_tokens(cmd_tokens, lineno, filename, line)
            if cmd_violation:
                violations.append(cmd_violation)

        return violations

    def _split_command_tokens(self, tokens: Sequence[str]) -> list[list[str]]:
        groups: list[list[str]] = []
        current: list[str] = []
        for token in tokens:
            if token in COMMAND_DELIMITERS:
                if current:
                    groups.append(current)
                    current = []
            else:
                current.append(token)
        if current:
            groups.append(current)
        return groups

    def _check_command_tokens(
        self, tokens: list[str], lineno: int, filename: str, original_line: str
    ) -> SafetyViolation | None:
        # Strip variable assignments at start (e.g. VAR=1 cmd ...)
        while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", tokens[0]):
            tokens = tokens[1:]

        if not tokens:
            return None

        full_cmd_str = " ".join(tokens)

        # 1. Skip echo / printf statements (strings printed to user)
        if tokens[0] in ("echo", "printf"):
            return None

        # 2. sudo check: never permitted under any circumstance
        if any(t == "sudo" or t.startswith("sudo/") for t in tokens):
            return SafetyViolation(
                filename=filename,
                lineno=lineno,
                command=full_cmd_str,
                message=(
                    "Use of 'sudo' is strictly forbidden in lab scripts (EUID 0 check required)"
                ),
            )

        # 3. Check for nsx() invocation helper
        if tokens[0] == "nsx":
            return None

        # 4. Check for direct "ip netns exec np-<name>"
        if len(tokens) >= 4 and tokens[0] == "ip" and tokens[1] == "netns" and tokens[2] == "exec":
            target_ns = tokens[3].strip("\"'")
            if target_ns.startswith("np-") or target_ns in (
                '"$ns"',
                '"$1"',
                "$ns",
                "$1",
                '"np-$ns"',
                '"np-$1"',
            ):
                return None
            return SafetyViolation(
                filename=filename,
                lineno=lineno,
                command=full_cmd_str,
                message=(
                    f"ip netns exec must target a namespace with 'np-' prefix, got '{target_ns}'"
                ),
            )

        # 5. Check for veth creation with BOTH ends directly placed into np-* namespaces
        if len(tokens) >= 3 and tokens[0] == "ip" and tokens[1] == "link" and tokens[2] == "add":
            netns_args = [
                tokens[i + 1].strip("\"'")
                for i, t in enumerate(tokens)
                if t == "netns" and i + 1 < len(tokens)
            ]
            is_veth = "type" in tokens and "veth" in tokens and "peer" in tokens
            both_in_np = len(netns_args) == 2 and all(ns.startswith("np-") for ns in netns_args)
            if is_veth and both_in_np:
                return None
            return SafetyViolation(
                filename=filename,
                lineno=lineno,
                command=full_cmd_str,
                message=(
                    "ip link add must place BOTH veth endpoints directly into np-* namespaces "
                    "('ip link add A netns np-x type veth peer name B netns np-y')"
                ),
            )

        # 6. Check for safe namespace management (ip netns add/del np-*)
        if len(tokens) >= 3 and tokens[0] == "ip" and tokens[1] == "netns":
            action = tokens[2]
            if action in ("add", "del", "delete"):
                if len(tokens) >= 4:
                    target_ns = tokens[3].strip("\"'")
                    if (
                        target_ns.startswith("np-")
                        or target_ns in ('"$ns"', '"$1"', "$ns", "$1")
                        or '"np-' in target_ns
                    ):
                        return None
                    return SafetyViolation(
                        filename=filename,
                        lineno=lineno,
                        command=full_cmd_str,
                        message=(
                            f"ip netns {action} target must start with 'np-', got '{target_ns}'"
                        ),
                    )
                return None
            if action in ("list", "show", "identify"):
                return None

        # 7. Check for read-only host inspection commands (e.g. "iptables -S" host state check)
        cmd = tokens[0]
        if cmd in ("iptables", "iptables-legacy", "iptables-nft", "ip6tables"):
            mutating_flags = {
                "-A",
                "--append",
                "-I",
                "--insert",
                "-D",
                "--delete",
                "-R",
                "--replace",
                "-F",
                "--flush",
                "-Z",
                "--zero",
                "-N",
                "--new-chain",
                "-X",
                "--delete-chain",
                "-P",
                "--policy",
            }
            has_mutating = any(t in mutating_flags for t in tokens)
            has_readonly = any(
                t in ("-S", "--list-rules", "-L", "--list", "-V", "--version") for t in tokens
            )
            if has_readonly and not has_mutating:
                return None

        # 8. Check for forbidden commands applied to host namespace
        if cmd in FORBIDDEN_HOST_COMMANDS:
            return SafetyViolation(
                filename=filename,
                lineno=lineno,
                command=full_cmd_str,
                message=f"Command '{cmd}' invoked outside nsx() or 'ip netns exec np-'",
            )

        if cmd == "ip" and len(tokens) > 1 and tokens[1] in FORBIDDEN_IP_SUBCOMMANDS:
            return SafetyViolation(
                filename=filename,
                lineno=lineno,
                command=full_cmd_str,
                message=f"'ip {tokens[1]}' invoked outside nsx() or 'ip netns exec np-'",
            )

        return None

    # ------------------------------------------------------------------
    # Python Script Linting
    # ------------------------------------------------------------------

    def lint_python_code(self, code: str, filename: str = "<string>") -> list[SafetyViolation]:
        """Lint raw Python script content using AST parsing."""
        violations: list[SafetyViolation] = []
        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as exc:
            violations.append(
                SafetyViolation(
                    filename=filename,
                    lineno=exc.lineno or 1,
                    command="<syntax-error>",
                    message=f"Python syntax error: {exc.msg}",
                )
            )
            return violations

        class PythonCallVisitor(ast.NodeVisitor):
            def __init__(self, outer: LabSafetyLinter) -> None:
                self.outer = outer

            def visit_Call(self, node: ast.Call) -> None:
                func_id = self._get_callable_name(node.func)
                if func_id in (
                    "subprocess.run",
                    "subprocess.Popen",
                    "subprocess.call",
                    "subprocess.check_call",
                    "subprocess.check_output",
                    "os.system",
                    "os.popen",
                ):
                    self._check_invocation(node, func_id)
                self.generic_visit(node)

            def _get_callable_name(self, node: ast.AST) -> str:
                if isinstance(node, ast.Name):
                    return node.id
                if isinstance(node, ast.Attribute):
                    val = self._get_callable_name(node.value)
                    return f"{val}.{node.attr}" if val else node.attr
                return ""

            def _check_invocation(self, node: ast.Call, func_id: str) -> None:
                if not node.args:
                    return
                first_arg = node.args[0]
                lineno = getattr(node, "lineno", 1)

                # Case 1: String argument (os.system or subprocess.run shell=True)
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    sub_violations = self.outer.lint_shell_code(
                        first_arg.value, filename=f"{filename}:{lineno}"
                    )
                    for v in sub_violations:
                        violations.append(
                            SafetyViolation(
                                filename=filename,
                                lineno=lineno,
                                command=v.command,
                                message=f"Python {func_id} executes unsafe command: {v.message}",
                            )
                        )
                # Case 2: List of strings (e.g. subprocess.run(["iptables", ...]))
                elif isinstance(first_arg, (ast.List, ast.Tuple)):
                    tokens: list[str] = []
                    for el in first_arg.elts:
                        if isinstance(el, ast.Constant) and isinstance(el.value, str):
                            tokens.append(el.value)
                        else:
                            tokens.append("<dynamic>")

                    token_violation = self.outer._check_command_tokens(
                        tokens, lineno, filename, " ".join(tokens)
                    )
                    if token_violation:
                        violations.append(
                            SafetyViolation(
                                filename=filename,
                                lineno=lineno,
                                command=token_violation.command,
                                message=(
                                    f"Python {func_id} executes unsafe command: "
                                    f"{token_violation.message}"
                                ),
                            )
                        )

        visitor = PythonCallVisitor(self)
        visitor.visit(tree)
        return violations

    # ------------------------------------------------------------------
    # File & Directory Scanning
    # ------------------------------------------------------------------

    def lint_file(self, file_path: Path) -> list[SafetyViolation]:
        """Lint a single .sh or .py file."""
        if not file_path.is_file():
            return []
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = file_path.read_text(encoding="latin-1")

        if file_path.suffix == ".sh":
            return self.lint_shell_code(content, filename=str(file_path))
        if file_path.suffix == ".py":
            return self.lint_python_code(content, filename=str(file_path))
        return []

    def scan_directory(self, directory: Path) -> dict[str, list[SafetyViolation]]:
        """Scan directory for *.sh and *.py files and return map of violations."""
        results: dict[str, list[SafetyViolation]] = {}
        if not directory.exists() or not directory.is_dir():
            return results

        for path in directory.rglob("*"):
            if path.is_file() and path.suffix in (".sh", ".py"):
                file_violations = self.lint_file(path)
                if file_violations:
                    results[str(path)] = file_violations
        return results


# ======================================================================
# Unit Tests for Lab Safety Linter
# ======================================================================


def test_linter_catches_sudo_in_shell() -> None:
    linter = LabSafetyLinter()
    bad_snippets = [
        "sudo iptables -L",
        "sudo bash setup.sh",
        "echo 'Running' && sudo ip netns exec np-client ping 10.0.0.1",
        "nsx client sudo ip addr show",
    ]
    for snippet in bad_snippets:
        violations = linter.lint_shell_code(snippet)
        assert len(violations) > 0, f"Expected violation for '{snippet}'"
        assert any("sudo" in v.message.lower() for v in violations)


def test_linter_catches_host_iptables() -> None:
    linter = LabSafetyLinter()
    violations = linter.lint_shell_code("iptables -A INPUT -p tcp --dport 80 -j DROP")
    assert len(violations) == 1
    assert "iptables" in violations[0].message


def test_linter_catches_host_nft() -> None:
    linter = LabSafetyLinter()
    violations = linter.lint_shell_code("nft add table inet filter")
    assert len(violations) == 1
    assert "nft" in violations[0].message


def test_linter_catches_host_ip_route() -> None:
    linter = LabSafetyLinter()
    violations = linter.lint_shell_code("ip route add default via 192.168.1.1")
    assert len(violations) == 1
    assert "ip route" in violations[0].message


def test_linter_catches_host_ip_addr() -> None:
    linter = LabSafetyLinter()
    violations = linter.lint_shell_code("ip addr add 10.200.1.2/24 dev eth0")
    assert len(violations) == 1
    assert "ip addr" in violations[0].message


def test_linter_catches_host_ip_link_set() -> None:
    linter = LabSafetyLinter()
    violations = linter.lint_shell_code("ip link set dev eth0 up")
    assert len(violations) == 1
    assert "ip link" in violations[0].message


def test_linter_catches_host_sysctl() -> None:
    linter = LabSafetyLinter()
    violations = linter.lint_shell_code("sysctl -w net.ipv4.ip_forward=1")
    assert len(violations) == 1
    assert "sysctl" in violations[0].message


def test_linter_catches_host_tc() -> None:
    linter = LabSafetyLinter()
    violations = linter.lint_shell_code("tc qdisc add dev eth0 root netem delay 50ms")
    assert len(violations) == 1
    assert "tc" in violations[0].message


def test_linter_catches_veth_with_host_endpoint() -> None:
    linter = LabSafetyLinter()
    bad_veth_commands = [
        "ip link add veth0 type veth peer name veth1",
        "ip link add veth0 netns np-client type veth peer name veth1",
        "ip link add veth0 netns client type veth peer name veth1 netns gw",  # missing np- prefix
    ]
    for cmd in bad_veth_commands:
        violations = linter.lint_shell_code(cmd)
        assert len(violations) >= 1, f"Expected violation for '{cmd}'"
        assert any("veth" in v.message.lower() for v in violations)


def test_linter_catches_non_np_namespace_target() -> None:
    linter = LabSafetyLinter()
    violations = linter.lint_shell_code("ip netns exec client-ns ip addr show")
    assert len(violations) == 1
    assert "np-" in violations[0].message


def test_linter_catches_chained_host_commands() -> None:
    linter = LabSafetyLinter()
    snippet = "echo 'Configuring network...' && iptables -F"
    violations = linter.lint_shell_code(snippet)
    assert len(violations) == 1
    assert "iptables" in violations[0].message


def test_linter_catches_command_substitution_host_command() -> None:
    linter = LabSafetyLinter()
    snippet = "GW=$(ip route show default | awk '{print $3}')"
    violations = linter.lint_shell_code(snippet)
    assert len(violations) >= 1
    assert any("ip route" in v.message for v in violations)


def test_linter_catches_python_subprocess_violations() -> None:
    linter = LabSafetyLinter()
    bad_py = """
import subprocess
import os

subprocess.run(["iptables", "-A", "INPUT", "-j", "DROP"])
subprocess.run(["ip", "route", "add", "default", "via", "10.0.0.1"])
os.system("sysctl -w net.ipv4.ip_forward=1")
subprocess.Popen(["sudo", "ip", "netns", "list"])
"""
    violations = linter.lint_python_code(bad_py)
    assert len(violations) == 4


def test_linter_accepts_clean_namespace_commands() -> None:
    linter = LabSafetyLinter()
    clean_snippet = """
#!/usr/bin/env bash
set -euo pipefail

# Helper function
nsx() {
    local ns="$1"
    shift
    ip netns exec "np-$ns" "$@"
}

# Namespace creation
ip netns add np-client
ip netns add np-gw
ip netns add np-server

# Dual-namespace veth creation
ip link add veth-client netns np-client type veth peer name veth-gw-c netns np-gw
ip link add veth-gw-s netns np-gw type veth peer name veth-server netns np-server

# Network operations via nsx
nsx client ip link set dev lo up
nsx client ip addr add 10.200.1.2/24 dev veth-client
nsx client ip route add default via 10.200.1.1 dev veth-client

# Gateway sysctl via explicit ip netns exec np-
ip netns exec np-gw sysctl -w net.ipv4.ip_forward=1
nsx gw ip route add blackhole 192.0.2.0/24
nsx gw ip route add blackhole 198.51.100.0/24

echo "Lab setup finished without touching host network"
"""
    violations = linter.lint_shell_code(clean_snippet)
    assert violations == []


def test_linter_accepts_clean_python_code() -> None:
    linter = LabSafetyLinter()
    clean_py = """
import subprocess

# Safe execution inside np-* namespace
subprocess.run(["ip", "netns", "exec", "np-client", "ip", "addr", "show"])
subprocess.run(["nsx", "client", "ping", "-c", "2", "10.200.2.2"])
# Comment mentioning sudo or iptables should be ignored
"""
    violations = linter.lint_python_code(clean_py)
    assert violations == []


def test_scan_lab_directory_passes() -> None:
    """Scans all *.sh and *.py files in the lab/ directory to verify zero safety violations."""
    repo_root = Path(__file__).resolve().parent.parent
    lab_dir = repo_root / "lab"
    if not lab_dir.exists():
        pytest.skip("lab/ directory not created yet")

    linter = LabSafetyLinter()
    results = linter.scan_directory(lab_dir)

    all_violations: list[str] = []
    for _file_path, file_violations in results.items():
        for v in file_violations:
            all_violations.append(str(v))

    assert all_violations == [], (
        f"Found {len(all_violations)} safety violations in lab/:\n" + "\n".join(all_violations)
    )


def test_scan_scripts_directory_passes() -> None:
    """Scans all *.sh and *.py files in the scripts/ directory to verify zero safety violations."""
    repo_root = Path(__file__).resolve().parent.parent
    scripts_dir = repo_root / "scripts"
    if not scripts_dir.exists():
        pytest.skip("scripts/ directory not found")

    linter = LabSafetyLinter()
    results = linter.scan_directory(scripts_dir)

    all_violations: list[str] = []
    for _file_path, file_violations in results.items():
        for v in file_violations:
            all_violations.append(str(v))

    assert all_violations == [], (
        f"Found {len(all_violations)} safety violations in scripts/:\n" + "\n".join(all_violations)
    )


def test_setup_script_structure_and_constraints() -> None:
    """Validates that lab/setup.sh satisfies all required hard constraints."""
    repo_root = Path(__file__).resolve().parent.parent
    setup_file = repo_root / "lab" / "setup.sh"
    if not setup_file.exists():
        pytest.skip("lab/setup.sh not created yet")

    content = setup_file.read_text(encoding="utf-8")

    # 1. EUID check at start without calling sudo
    assert "EUID" in content, "setup.sh must check EUID"
    assert "exit 1" in content, "setup.sh must exit on non-root EUID"

    # 2. Never invoke sudo
    linter = LabSafetyLinter()
    violations = linter.lint_file(setup_file)
    assert violations == [], f"Safety violations in setup.sh: {violations}"

    # 3. Helper function nsx defined
    assert "nsx()" in content or "nsx ()" in content, "setup.sh must define nsx() helper"

    # 4. Namespaces created
    for ns in ("np-client", "np-gw", "np-server"):
        assert ns in content, f"setup.sh must configure namespace {ns}"

    # 5. Dual-netns veth creation
    assert "type veth peer" in content, "setup.sh must create veth peers"

    # 6. Addresses assigned
    assert "10.200.1.2/24" in content, "client IP missing"
    assert "10.200.1.1/24" in content, "gw client-side IP missing"
    assert "10.200.2.1/24" in content, "gw server-side IP missing"
    assert "10.200.2.2/24" in content, "server IP missing"

    # 7. Default routes configured
    assert "default via 10.200.1.1" in content, "client default route missing"
    assert "default via 10.200.2.1" in content, "server default route missing"

    # 8. Forwarding enabled strictly on np-gw
    assert "ip netns exec np-gw sysctl -w net.ipv4.ip_forward=1" in content or (
        "np-gw" in content and "net.ipv4.ip_forward=1" in content
    )

    # 9. Blackhole routes in np-gw for documentation addresses
    assert "blackhole 192.0.2.0/24" in content, "blackhole route for 192.0.2.0/24 missing"
    assert "blackhole 198.51.100.0/24" in content, "blackhole route for 198.51.100.0/24 missing"

    # 10. Ping verification client -> server
    assert "ping" in content and "10.200.2.2" in content, "ping verification missing"

    # 11. Safety reminder at the end
    assert "outside" in content.lower() or "host" in content.lower(), "safety reminder missing"


def test_teardown_script_structure_and_constraints() -> None:
    """Validates that lab/teardown.sh satisfies all required hard constraints."""
    repo_root = Path(__file__).resolve().parent.parent
    teardown_file = repo_root / "lab" / "teardown.sh"
    if not teardown_file.exists():
        pytest.skip("lab/teardown.sh not created yet")

    content = teardown_file.read_text(encoding="utf-8")

    # 1. EUID check at start
    assert "EUID" in content, "teardown.sh must check EUID"
    assert "exit 1" in content, "teardown.sh must exit on non-root EUID"

    # 2. Never invoke sudo
    linter = LabSafetyLinter()
    violations = linter.lint_file(teardown_file)
    assert violations == [], f"Safety violations in teardown.sh: {violations}"

    # 3. Only delete namespaces starting with np-
    assert "np-" in content, "teardown.sh must restrict deletions to np- prefix"

    # 4. Cleans up /tmp/np-pids
    assert "np-pids" in content, "teardown.sh must stop services from /tmp/np-pids"


def test_linter_allows_readonly_iptables_listing() -> None:
    """Verifies that read-only iptables queries (like iptables -S) are allowed for verification."""
    linter = LabSafetyLinter()
    clean_snippets = [
        "HOST_BEFORE=$(iptables -S 2>/dev/null || true)",
        "iptables -S",
        "iptables --list-rules",
        "iptables -L",
    ]
    for snippet in clean_snippets:
        violations = linter.lint_shell_code(snippet)
        assert violations == [], f"Expected clean check for '{snippet}', got {violations}"

    # Verify mutating iptables commands on host are STILL blocked
    bad_snippets = [
        "iptables -A INPUT -j DROP",
        "iptables -F",
        "iptables -X",
        "iptables -t nat -F",
        "iptables -P FORWARD DROP",
    ]
    for snippet in bad_snippets:
        violations = linter.lint_shell_code(snippet)
        assert len(violations) > 0, f"Expected violation for '{snippet}'"


def test_services_script_structure_and_constraints() -> None:
    """Validates that lab/services.sh satisfies all required hard constraints."""
    repo_root = Path(__file__).resolve().parent.parent
    services_file = repo_root / "lab" / "services.sh"
    if not services_file.exists():
        pytest.skip("lab/services.sh not created yet")

    content = services_file.read_text(encoding="utf-8")

    # 1. EUID check
    assert "EUID" in content, "services.sh must check EUID"
    assert "exit 1" in content, "services.sh must exit on non-root EUID"

    # 2. Never invoke sudo
    linter = LabSafetyLinter()
    violations = linter.lint_file(services_file)
    assert violations == [], f"Safety violations in services.sh: {violations}"

    # 3. Target ports configured: 21, 22, 25, 443, 587, 80 (canary), 53 (dns)
    for port in ("21", "22", "25", "443", "587"):
        assert port in content, f"services.sh must configure port {port}"
    assert "canary" in content, "services.sh must start canary server"
    assert "dns_server" in content, "services.sh must start dns server"

    # 4. Writes PIDs to lab/run/pids (and /tmp/np-pids)
    assert "pids" in content, "services.sh must write to pids file"
    assert "/tmp/np-pids" in content, "services.sh must write to /tmp/np-pids"

    # 5. Detached startup and logs in lab/run/*.log
    assert "nohup" in content or "setsid" in content, "services.sh must start detached"
    assert ".log" in content, "services.sh must redirect logs to .log files"

    # 6. Verifies listeners with ss -ltnp
    assert "ss -ltnp" in content, "services.sh must verify listeners with ss -ltnp"

    # 7. Supports status and stop subcommands
    assert "status" in content, "services.sh must support status subcommand"
    assert "stop" in content, "services.sh must support stop subcommand"


def test_status_script_structure_and_constraints() -> None:
    """Validates that lab/status.sh satisfies all required safety constraints and outputs."""
    repo_root = Path(__file__).resolve().parent.parent
    status_file = repo_root / "lab" / "status.sh"
    assert status_file.exists(), "lab/status.sh must exist"

    content = status_file.read_text(encoding="utf-8")

    # 1. EUID check
    assert "EUID" in content, "status.sh must check EUID"
    assert "exit 1" in content, "status.sh must exit on non-root EUID"

    # 2. Never invoke sudo
    linter = LabSafetyLinter()
    violations = linter.lint_file(status_file)
    assert violations == [], f"Safety violations in status.sh: {violations}"

    # 3. Reports namespaces and addresses
    assert "ip netns list" in content, "status.sh must query namespaces"
    assert "addr" in content, "status.sh must query interface addresses"

    # 4. Reports active scenario from lab/run/active_scenario
    assert "active_scenario" in content, "status.sh must read active_scenario"

    # 5. Queries iptables in np-gw (filter & nat)
    assert "iptables -S" in content, "status.sh must query filter table in np-gw"
    assert "iptables -t nat -S" in content, "status.sh must query nat table in np-gw"

    # 6. Checks PIDs and sockets
    assert "pids" in content, "status.sh must check service PIDs"
    assert "ss -ltnp" in content, "status.sh must query active listeners"


def test_scenario_script_structure_and_constraints() -> None:
    """Validates that lab/scenario.sh satisfies all required hard constraints."""
    repo_root = Path(__file__).resolve().parent.parent
    scenario_file = repo_root / "lab" / "scenario.sh"
    if not scenario_file.exists():
        pytest.skip("lab/scenario.sh not created yet")

    content = scenario_file.read_text(encoding="utf-8")

    # 1. EUID check
    assert "EUID" in content, "scenario.sh must check EUID"
    assert "exit 1" in content, "scenario.sh must exit on non-root EUID"

    # 2. Never invoke sudo
    linter = LabSafetyLinter()
    violations = linter.lint_file(scenario_file)
    assert violations == [], f"Safety violations in scenario.sh: {violations}"

    # 3. All required scenarios handled including composite 'campus'
    required_scenarios = [
        "clean",
        "drop-smtp",
        "reset-smtp",
        "icmp-admin",
        "icmp-port-unreach",
        "dns-dnat",
        "nxdomain-rewrite",
        "http-proxy",
        "campus",
    ]
    for sc in required_scenarios:
        assert sc in content, f"scenario.sh must implement scenario '{sc}'"

    # 4. Flushes rules in np-gw
    assert "iptables -F" in content, "scenario.sh must flush rules in np-gw"
    assert "iptables -t nat -F" in content, "scenario.sh must flush nat table in np-gw"

    # 5. Confirms host iptables unchanged
    assert "iptables -S" in content, "scenario.sh must inspect host iptables state"
    assert "UNCHANGED" in content, "scenario.sh must confirm host state is unchanged"

    # 6. Exclusivity notice and active_scenario recording
    assert "Scenarios are exclusive: all rules in np-gw are flushed first" in content, (
        "scenario.sh must print exclusivity notice at start"
    )
    assert "active_scenario" in content, "scenario.sh must record active scenario"
    assert "--list" in content, "scenario.sh must support --list flag"


def test_campus_scenario_yaml_configuration() -> None:
    """Validates that lab/scenarios.yaml includes campus scenario with expected verdicts."""
    repo_root = Path(__file__).resolve().parent.parent
    scenarios_yaml = repo_root / "lab" / "scenarios.yaml"
    assert scenarios_yaml.exists(), "lab/scenarios.yaml must exist"

    content = scenarios_yaml.read_text(encoding="utf-8")
    assert "name: campus" in content, "scenarios.yaml must include campus scenario"
    assert "BLOCKED_RESET" in content, "campus scenario must expect BLOCKED_RESET on port 25"
    assert "INTERCEPTED" in content, "campus scenario must expect INTERCEPTED DNS"
    assert "HEADERS_INJECTED" in content, "campus scenario must expect HEADERS_INJECTED HTTP"


def test_bootstrap_system_script_structure_and_constraints() -> None:
    """Validates that scripts/bootstrap-system.sh satisfies all safety rules and requirements."""
    repo_root = Path(__file__).resolve().parent.parent
    bootstrap_file = repo_root / "scripts" / "bootstrap-system.sh"
    assert bootstrap_file.exists(), "scripts/bootstrap-system.sh must exist"

    content = bootstrap_file.read_text(encoding="utf-8")

    # 1. EUID check at start without calling sudo
    assert "EUID" in content, "bootstrap-system.sh must check EUID"
    assert "sudo bash scripts/bootstrap-system.sh" in content, (
        "bootstrap-system.sh must advise user to run via sudo"
    )

    # 2. Never invoke sudo as a command
    linter = LabSafetyLinter()
    violations = linter.lint_file(bootstrap_file)
    assert violations == [], f"Safety violations in bootstrap-system.sh: {violations}"

    # 3. Required packages on apt
    required_packages = [
        "python3",
        "python3-venv",
        "python3-pip",
        "iproute2",
        "iptables",
        "curl",
        "ca-certificates",
        "iputils-ping",
    ]
    for pkg in required_packages:
        assert pkg in content, f"bootstrap-system.sh must install {pkg}"

    # 4. Non-apt instructions
    assert "dnf" in content, "bootstrap-system.sh must mention dnf for non-apt systems"
    assert "pacman" in content, "bootstrap-system.sh must mention pacman for non-apt systems"


def test_bootstrap_python_script_structure_and_constraints() -> None:
    """Validates that scripts/bootstrap-python.sh satisfies all safety rules and requirements."""
    repo_root = Path(__file__).resolve().parent.parent
    bootstrap_file = repo_root / "scripts" / "bootstrap-python.sh"
    assert bootstrap_file.exists(), "scripts/bootstrap-python.sh must exist"

    content = bootstrap_file.read_text(encoding="utf-8")

    # 1. Non-root EUID check (must NOT run as root)
    assert "EUID" in content, "bootstrap-python.sh must check EUID"
    assert "must NOT be run as root" in content or "eq 0" in content, (
        "bootstrap-python.sh must refuse execution if run as root"
    )

    # 2. Never invoke sudo
    linter = LabSafetyLinter()
    violations = linter.lint_file(bootstrap_file)
    assert violations == [], f"Safety violations in bootstrap-python.sh: {violations}"

    # 3. Virtual environment bootstrapping
    assert ".linux-venv" in content, "bootstrap-python.sh must target .linux-venv"
    assert "--without-pip" in content, "bootstrap-python.sh must create venv with --without-pip"
    assert "get-pip.py" in content, "bootstrap-python.sh must bootstrap with get-pip.py"
    assert "ensurepip" in content, "bootstrap-python.sh must fallback to ensurepip"
    assert ".[lab]" in content, "bootstrap-python.sh must install .[lab]"

    # 4. Verifications
    assert "netpolicy --version" in content or 'netpolicy" --version' in content
    assert "python -m netpolicy" in content or 'python" -m netpolicy' in content
    assert "matplotlib" in content and "yaml" in content and "rich" in content


def test_doctor_script_structure_and_constraints() -> None:
    """Validates that scripts/doctor.sh satisfies all safety rules and requirements."""
    repo_root = Path(__file__).resolve().parent.parent
    doctor_file = repo_root / "scripts" / "doctor.sh"
    assert doctor_file.exists(), "scripts/doctor.sh must exist"

    content = doctor_file.read_text(encoding="utf-8")

    # 1. Never invoke sudo
    linter = LabSafetyLinter()
    violations = linter.lint_file(doctor_file)
    assert violations == [], f"Safety violations in doctor.sh: {violations}"

    # 2. Required checks present
    assert "WSL1" in content or "wsl1" in content, "doctor.sh must detect WSL1"
    assert "WSL2" in content or "wsl2" in content, "doctor.sh must detect WSL2"
    assert "/mnt/" in content, "doctor.sh must check if repo is under /mnt/"
    assert "3.10" in content or "(3, 10)" in content, "doctor.sh must verify Python >= 3.10"
    assert ".linux-venv" in content, "doctor.sh must check .linux-venv"
    assert "netpolicy" in content, "doctor.sh must check netpolicy import"

    # 3. Tool checks
    for tool in ("ip", "iptables", "tc", "curl"):
        assert tool in content, f"doctor.sh must check for tool '{tool}'"

    # 4. iptables backend info
    assert "nf_tables" in content or "nft" in content, "doctor.sh must detect nf_tables"
    assert "legacy" in content, "doctor.sh must detect legacy iptables"

    # 5. Throwaway namespace self-test
    assert "np-doctor-" in content, "doctor.sh must use throwaway namespaces named np-doctor-<pid>"
    assert "trap" in content and "EXIT" in content, "doctor.sh must install cleanup trap on EXIT"
    assert "veth" in content, "doctor.sh must test veth creation"
    assert "REJECT" in content, "doctor.sh must test REJECT rule"
    assert "tcp-reset" in content, "doctor.sh must test tcp-reset reject"
    assert "nat" in content, "doctor.sh must test nat table rule"


def test_demo_script_structure_and_constraints() -> None:
    """Validates that scripts/demo.sh satisfies all safety rules and operational requirements."""
    repo_root = Path(__file__).resolve().parent.parent
    demo_file = repo_root / "scripts" / "demo.sh"
    assert demo_file.exists(), "scripts/demo.sh must exist"

    content = demo_file.read_text(encoding="utf-8")

    # 1. EUID check at start without calling sudo
    assert "EUID" in content, "demo.sh must check EUID"
    assert "exit 1" in content, "demo.sh must exit on non-root EUID"

    # 2. Never invoke sudo
    linter = LabSafetyLinter()
    violations = linter.lint_file(demo_file)
    assert violations == [], f"Safety violations in demo.sh: {violations}"

    # 3. Invokes core lab workflow components
    assert "doctor.sh" in content, "demo.sh must invoke doctor.sh"
    assert "setup.sh" in content, "demo.sh must invoke lab/setup.sh"
    assert "services.sh" in content, "demo.sh must invoke lab/services.sh"
    assert "scenario.sh" in content, "demo.sh must invoke lab/scenario.sh"
    assert "teardown.sh" in content, "demo.sh must invoke lab/teardown.sh"

    # 4. Executes audit strictly within namespace
    assert "ip netns exec np-client" in content, "demo.sh must run audits inside np-client"
    assert "audit" in content, "demo.sh must run netpolicy audit"
    assert "compare" in content, "demo.sh must run netpolicy compare"

    # 5. Output directory and report artifacts
    assert "demo-output" in content, "demo.sh must store reports in demo-output directory"
    assert "baseline.json" in content, "demo.sh must produce baseline.json"
    assert "tampered.json" in content, "demo.sh must produce tampered.json"

    # 6. Default and flexible scenario support
    assert "reset-smtp" in content, "demo.sh must default to reset-smtp scenario"

    # 7. Verification of expected exit codes and summary reporting
    assert "BASELINE_EC" in content, "demo.sh must track baseline audit exit code"
    assert "TAMPERED_EC" in content, "demo.sh must track tampered audit exit code"
    assert "COMPARE_EC" in content, "demo.sh must track compare command exit code"
    assert "PASS:" in content, "demo.sh must print single-line PASS indicator"
    assert "FAIL:" in content, "demo.sh must print single-line FAIL indicator"

    # 8. Cleanup trap and ownership preservation
    assert "trap cleanup" in content, "demo.sh must establish cleanup trap"
    assert "EXIT" in content and "INT" in content and "TERM" in content, (
        "demo.sh must trap on EXIT, INT, TERM"
    )
    assert "SUDO_UID" in content and "SUDO_GID" in content, (
        "demo.sh must chown output files back to SUDO_UID:SUDO_GID"
    )


def test_export_docs_script_structure_and_constraints() -> None:
    """Validates that scripts/export-docs.sh satisfies all safety rules and requirements."""
    repo_root = Path(__file__).resolve().parent.parent
    export_file = repo_root / "scripts" / "export-docs.sh"
    assert export_file.exists(), "scripts/export-docs.sh must exist"

    content = export_file.read_text(encoding="utf-8")

    # 1. Never invoke sudo and no safety violations
    linter = LabSafetyLinter()
    violations = linter.lint_file(export_file)
    assert violations == [], f"Safety violations in export-docs.sh: {violations}"

    # 2. Windows profile resolution via cmd.exe and wslpath
    assert "USERPROFILE" in content, "export-docs.sh must query USERPROFILE"
    assert "wslpath" in content, "export-docs.sh must invoke wslpath"
    assert "mkdir -p" in content, "export-docs.sh must create destination directory"

    # 3. Timestamped backup before copying
    assert ".bak" in content, "export-docs.sh must create .bak backup for existing files"

    # 4. Target files to export
    assert "netpolicy_master_guide.md" in content, (
        "export-docs.sh must export netpolicy_master_guide.md"
    )
    assert "PORTABILITY.md" in content, "export-docs.sh must export PORTABILITY.md"

    # 5. Fallback and custom destination support
    assert "wslpath -w" in content, "export-docs.sh must print Windows path via wslpath -w"
    assert "wsl$" in content or "wsl.localhost" in content or "unc_path" in content, (
        "export-docs.sh must provide UNC fallback"
    )
