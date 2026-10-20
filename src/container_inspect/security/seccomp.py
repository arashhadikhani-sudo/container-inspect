from __future__ import annotations

import argparse
import json
import os

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


# Linux Seccomp modes reported by /proc/<PID>/status.
SECCOMP_MODES: dict[int, str] = {
    0: "disabled",
    1: "strict",
    2: "filter",
}


class SeccompError(Exception):
    """Base exception for Seccomp inspection errors."""


class InvalidPIDError(SeccompError):
    """Raised when a process ID is invalid."""


class ProcessNotFoundError(SeccompError):
    """Raised when the requested process does not exist."""


class ProcessPermissionError(SeccompError):
    """Raised when the process status cannot be read due to permissions."""


class ProcessStatusError(SeccompError):
    """Raised when the process status file cannot be parsed or read."""


@dataclass(frozen=True, slots=True)
class SeccompInfo:
    """
    Seccomp information collected from /proc/<PID>/status.

    Attributes:
        pid: Process ID.
        name: Process name reported by the Linux kernel.
        mode: Numeric Seccomp mode.
        mode_name: Human-readable Seccomp mode.
        no_new_privs: Whether NoNewPrivs is enabled.
        filter_count: Number of installed Seccomp filters, if available.
    """

    pid: int
    name: str
    mode: int
    mode_name: str
    no_new_privs: bool
    filter_count: int | None = None

    @property
    def enabled(self) -> bool:
        """Return True if Seccomp is enabled."""
        return self.mode in (1, 2)

    @property
    def filter_mode(self) -> bool:
        """Return True if the process uses Seccomp filter mode."""
        return self.mode == 2

    @property
    def strict_mode(self) -> bool:
        """Return True if the process uses strict Seccomp mode."""
        return self.mode == 1

    @property
    def disabled(self) -> bool:
        """Return True if Seccomp is disabled."""
        return self.mode == 0

    def to_dict(self) -> dict[str, Any]:
        """Convert the Seccomp information into a dictionary."""
        result = asdict(self)

        # Include convenient derived properties in serialized output.
        result["enabled"] = self.enabled
        result["filter_mode"] = self.filter_mode
        result["strict_mode"] = self.strict_mode
        result["disabled"] = self.disabled

        return result


def validate_pid(pid: int) -> int:
    """
    Validate a Linux process ID.

    PID must be a positive integer. Booleans are rejected even though
    bool is a subclass of int in Python.
    """
    if isinstance(pid, bool) or not isinstance(pid, int):
        raise InvalidPIDError("PID must be an integer.")

    if pid <= 0:
        raise InvalidPIDError("PID must be greater than zero.")

    return pid


def parse_status_file(status_text: str) -> dict[str, str]:
    """
    Parse the contents of /proc/<PID>/status.

    Each status entry normally follows this format:

        Name:   bash
        Seccomp:        2
        NoNewPrivs:     1

    Returns:
        A dictionary mapping status field names to their values.
    """
    if not isinstance(status_text, str):
        raise TypeError("status_text must be a string.")

    fields: dict[str, str] = {}

    for line in status_text.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if key:
            fields[key] = value

    return fields


def parse_integer(
    value: str | None,
    field_name: str,
    *,
    default: int | None = None,
) -> int:
    """
    Parse an integer from a /proc status field.

    Args:
        value: Text to parse.
        field_name: Name used in error messages.
        default: Optional value to return when the field is missing.
    """
    if value is None or value == "":
        if default is not None:
            return default

        raise ProcessStatusError(
            f"Required status field '{field_name}' is missing."
        )

    try:
        result = int(value, 10)
    except ValueError as exc:
        raise ProcessStatusError(
            f"Invalid integer in status field '{field_name}': {value!r}"
        ) from exc

    return result


def parse_seccomp_mode(value: str | None) -> int:
    """
    Parse and validate the Seccomp mode.

    Linux normally reports:
        0 = disabled
        1 = strict
        2 = filter
    """
    mode = parse_integer(value, "Seccomp")

    if mode not in SECCOMP_MODES:
        raise ProcessStatusError(
            f"Unknown Seccomp mode {mode}. "
            f"Expected one of: {', '.join(map(str, SECCOMP_MODES))}."
        )

    return mode


def parse_boolean_status(
    value: str | None,
    field_name: str,
    *,
    default: bool = False,
) -> bool:
    """
    Parse a Linux boolean-style status field.

    NoNewPrivs is normally 0 or 1.
    """
    if value is None or value == "":
        return default

    parsed = parse_integer(value, field_name)

    if parsed not in (0, 1):
        raise ProcessStatusError(
            f"Invalid value for '{field_name}': expected 0 or 1, "
            f"received {parsed}."
        )

    return parsed == 1


def read_process_status(
    pid: int,
    proc_root: str | Path = "/proc",
) -> dict[str, str]:
    """
    Read and parse /proc/<PID>/status.

    Args:
        pid: Linux process ID.
        proc_root: Root of the proc filesystem. Defaults to /proc.
                   A custom path is useful for testing.

    Raises:
        InvalidPIDError: If the PID is invalid.
        ProcessNotFoundError: If the process does not exist.
        ProcessPermissionError: If access is denied.
        ProcessStatusError: If the file cannot be read.
    """
    validate_pid(pid)

    status_path = Path(proc_root) / str(pid) / "status"

    try:
        status_text = status_path.read_text(encoding="utf-8")

    except FileNotFoundError as exc:
        raise ProcessNotFoundError(
            f"Process {pid} was not found, or its status file does not exist."
        ) from exc

    except PermissionError as exc:
        raise ProcessPermissionError(
            f"Permission denied while reading {status_path}."
        ) from exc

    except OSError as exc:
        raise ProcessStatusError(
            f"Could not read process status from {status_path}: {exc}"
        ) from exc

    return parse_status_file(status_text)


def inspect_seccomp(
    pid: int,
    proc_root: str | Path = "/proc",
) -> SeccompInfo:
    """
    Inspect the Seccomp configuration of a Linux process.

    The function reads information from /proc/<PID>/status and returns
    a SeccompInfo object.

    Args:
        pid: Linux process ID.
        proc_root: Root of the proc filesystem.

    Returns:
        SeccompInfo containing the process's Seccomp status.

    Example:
        info = inspect_seccomp(1234)
        print(info.mode_name)
        print(info.enabled)
    """
    validate_pid(pid)

    fields = read_process_status(pid, proc_root)

    name = fields.get("Name", "unknown")
    mode = parse_seccomp_mode(fields.get("Seccomp"))

    no_new_privs = parse_boolean_status(
        fields.get("NoNewPrivs"),
        "NoNewPrivs",
        default=False,
    )

    filter_count: int | None = None

    # Seccomp_filters is available on Linux kernels that expose this field.
    # Older kernels may omit it.
    if "Seccomp_filters" in fields:
        filter_count = parse_integer(
            fields["Seccomp_filters"],
            "Seccomp_filters",
        )

        if filter_count < 0:
            raise ProcessStatusError(
                "Seccomp_filters cannot be negative."
            )

    return SeccompInfo(
        pid=pid,
        name=name,
        mode=mode,
        mode_name=SECCOMP_MODES[mode],
        no_new_privs=no_new_privs,
        filter_count=filter_count,
    )


def format_seccomp_report(info: SeccompInfo) -> str:
    """
    Format Seccomp information as a human-readable report.
    """
    lines = [
        f"Process:       {info.name}",
        f"PID:           {info.pid}",
        f"Seccomp mode:  {info.mode_name} ({info.mode})",
        f"Seccomp:       {'enabled' if info.enabled else 'disabled'}",
        f"NoNewPrivs:    {'enabled' if info.no_new_privs else 'disabled'}",
    ]

    if info.filter_count is not None:
        lines.append(f"Filter count:  {info.filter_count}")

    if info.strict_mode:
        lines.append(
            "Note:          Strict mode permits only a limited set of system calls."
        )
    elif info.filter_mode:
        lines.append(
            "Note:          Filter mode uses Seccomp filters to restrict system calls."
        )
    else:
        lines.append(
            "Note:          No Seccomp restrictions are reported for this process."
        )

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """
    Command-line interface for inspecting process Seccomp status.

    Examples:
        python -m container_inspect.security.seccomp 1234
        python -m container_inspect.security.seccomp 1234 --json
    """
    parser = argparse.ArgumentParser(
        description="Inspect Linux Seccomp status for a process."
    )

    parser.add_argument(
        "pid",
        type=int,
        help="Process ID to inspect.",
    )

    parser.add_argument(
        "--proc-root",
        default="/proc",
        help="Path to the proc filesystem root (default: /proc).",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )

    args = parser.parse_args(argv)

    try:
        info = inspect_seccomp(
            pid=args.pid,
            proc_root=args.proc_root,
        )

    except SeccompError as exc:
        parser.exit(status=1, message=f"Error: {exc}\n")

    if args.json:
        print(json.dumps(info.to_dict(), indent=2))
    else:
        print(format_seccomp_report(info))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
