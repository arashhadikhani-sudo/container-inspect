"""Linux capabilities inspection and decoding.

This module provides utilities for decoding Linux capability bitmasks,
inspecting process capabilities through the proc filesystem, and
representing capability information in a structured format.

No third-party dependencies are required.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final


# Linux capability bit numbers and their corresponding names.
CAPABILITY_NAMES: Final[dict[int, str]] = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

CAPABILITY_BITS: Final[dict[str, int]] = {
    name: bit for bit, name in CAPABILITY_NAMES.items()
}

CAPABILITY_FIELDS: Final[dict[str, str]] = {
    "CapEff": "effective",
    "CapPrm": "permitted",
    "CapInh": "inheritable",
    "CapBnd": "bounding",
    "CapAmb": "ambient",
}


@dataclass(frozen=True, slots=True)
class ProcessCapabilities:
    """Represent the capability sets of a Linux process.

    Attributes:
        pid: Linux process ID.
        effective: Capabilities currently effective for the process.
        permitted: Capabilities the process is permitted to make effective.
        inheritable: Capabilities available for inheritance.
        bounding: Capabilities restricted by the bounding set.
        ambient: Capabilities in the ambient set.
    """

    pid: int
    effective: frozenset[str]
    permitted: frozenset[str]
    inheritable: frozenset[str]
    bounding: frozenset[str]
    ambient: frozenset[str]

    @property
    def effective_count(self) -> int:
        """Return the number of effective capabilities."""
        return len(self.effective)

    @property
    def is_privileged(self) -> bool:
        """Check whether CAP_SYS_ADMIN is effective.

        This is a narrow indicator, not a complete security assessment.
        """
        return "CAP_SYS_ADMIN" in self.effective

    @property
    def has_net_admin(self) -> bool:
        """Check whether CAP_NET_ADMIN is effective."""
        return "CAP_NET_ADMIN" in self.effective

    @property
    def has_net_raw(self) -> bool:
        """Check whether CAP_NET_RAW is effective."""
        return "CAP_NET_RAW" in self.effective

    def to_dict(self) -> dict[str, object]:
        """Convert capability information to JSON-compatible data."""
        return {
            "pid": self.pid,
            "effective": sorted(self.effective),
            "permitted": sorted(self.permitted),
            "inheritable": sorted(self.inheritable),
            "bounding": sorted(self.bounding),
            "ambient": sorted(self.ambient),
            "effective_count": self.effective_count,
            "is_privileged": self.is_privileged,
            "has_net_admin": self.has_net_admin,
            "has_net_raw": self.has_net_raw,
        }


def _validate_pid(pid: int) -> None:
    """Validate a Linux process ID."""
    if isinstance(pid, bool) or not isinstance(pid, int):
        raise TypeError("PID must be an integer.")

    if pid <= 0:
        raise ValueError("PID must be greater than zero.")


def decode_capability_mask(mask: int) -> frozenset[str]:
    """Decode an integer Linux capability bitmask.

    Args:
        mask: A non-negative integer capability bitmask.

    Returns:
        A frozenset of recognized capability names.

    Raises:
        TypeError: If mask is not an integer.
        ValueError: If mask is negative.
    """
    if isinstance(mask, bool) or not isinstance(mask, int):
        raise TypeError("Capability mask must be an integer.")

    if mask < 0:
        raise ValueError("Capability mask cannot be negative.")

    return frozenset(
        name
        for bit, name in CAPABILITY_NAMES.items()
        if mask & (1 << bit)
    )


def decode_capability_hex(value: str) -> frozenset[str]:
    """Decode a hexadecimal Linux capability bitmask.

    Examples:
        >>> decode_capability_hex("400")
        frozenset({'CAP_NET_BIND_SERVICE'})

        >>> decode_capability_hex("0x400")
        frozenset({'CAP_NET_BIND_SERVICE'})

    Args:
        value: A hexadecimal string, optionally prefixed with 0x.

    Returns:
        A frozenset of recognized capability names.

    Raises:
        TypeError: If value is not a string.
        ValueError: If value is empty or invalid.
    """
    if not isinstance(value, str):
        raise TypeError("Capability mask must be a string.")

    value = value.strip()

    if value.lower().startswith("0x"):
        value = value[2:]

    if not value:
        raise ValueError("Capability mask cannot be empty.")

    try:
        mask = int(value, 16)
    except ValueError as exc:
        raise ValueError(
            f"Invalid hexadecimal capability mask: {value!r}"
        ) from exc

    return decode_capability_mask(mask)


def encode_capabilities(capabilities: set[str] | frozenset[str]) -> int:
    """Encode capability names into an integer bitmask.

    Args:
        capabilities: Capability names such as CAP_CHOWN.

    Returns:
        The resulting integer bitmask.

    Raises:
        TypeError: If capabilities is not a set or frozenset.
        ValueError: If an unknown capability name is supplied.
    """
    if not isinstance(capabilities, (set, frozenset)):
        raise TypeError("Capabilities must be a set or frozenset.")

    mask = 0

    for name in capabilities:
        if not isinstance(name, str):
            raise TypeError("Every capability name must be a string.")

        try:
            bit = CAPABILITY_BITS[name]
        except KeyError as exc:
            raise ValueError(
                f"Unknown Linux capability: {name!r}"
            ) from exc

        mask |= 1 << bit

    return mask


def get_capability_name(bit: int) -> str | None:
    """Return the capability name for a bit number.

    Returns None when the bit is not in the known capability table.
    """
    if isinstance(bit, bool) or not isinstance(bit, int):
        raise TypeError("Capability bit must be an integer.")

    if bit < 0:
        raise ValueError("Capability bit cannot be negative.")

    return CAPABILITY_NAMES.get(bit)


def get_capability_bit(name: str) -> int | None:
    """Return the bit number for a capability name.

    Returns None when the name is not recognized.
    """
    if not isinstance(name, str):
        raise TypeError("Capability name must be a string.")

    return CAPABILITY_BITS.get(name)


def read_process_capabilities(
    pid: int,
    proc_root: str | Path = "/proc",
) -> ProcessCapabilities:
    """Read the capability sets of a Linux process.

    Reads CapEff, CapPrm, CapInh, CapBnd and CapAmb from:

        <proc_root>/<pid>/status

    Args:
        pid: Linux process ID.
        proc_root: Root directory of the proc filesystem. This can be
            overridden to support testing or alternative proc mounts.

    Returns:
        A ProcessCapabilities object.

    Raises:
        TypeError: If pid is not an integer.
        ValueError: If pid is not positive.
        FileNotFoundError: If the process status file does not exist.
        PermissionError: If the file cannot be accessed.
        RuntimeError: If required fields are missing or malformed.
        OSError: For other filesystem errors.
    """
    _validate_pid(pid)

    status_path = Path(proc_root) / str(pid) / "status"

    raw_fields: dict[str, str] = {}

    with status_path.open("r", encoding="utf-8") as status_file:
        for line in status_file:
            key, separator, value = line.partition(":")

            if not separator:
                continue

            if key in CAPABILITY_FIELDS:
                raw_fields[key] = value.strip()

    missing_fields = set(CAPABILITY_FIELDS) - raw_fields.keys()

    if missing_fields:
        missing = ", ".join(sorted(missing_fields))
        raise RuntimeError(
            f"Missing capability fields in {status_path}: {missing}"
        )

    decoded: dict[str, frozenset[str]] = {}

    for proc_field, attribute_name in CAPABILITY_FIELDS.items():
        try:
            decoded[attribute_name] = decode_capability_hex(
                raw_fields[proc_field]
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"Invalid {proc_field} value in {status_path}: "
                f"{raw_fields[proc_field]!r}"
            ) from exc

    return ProcessCapabilities(
        pid=pid,
        effective=decoded["effective"],
        permitted=decoded["permitted"],
        inheritable=decoded["inheritable"],
        bounding=decoded["bounding"],
        ambient=decoded["ambient"],
    )


def format_capabilities(
    capabilities: ProcessCapabilities,
) -> str:
    """Format process capabilities as a readable report."""
    sections = [
        f"Process ID: {capabilities.pid}",
        f"Effective capabilities ({len(capabilities.effective)}):",
    ]

    sections.extend(
        f"  - {name}"
        for name in sorted(capabilities.effective)
    )

    sections.append(
        f"Permitted capabilities ({len(capabilities.permitted)}):"
    )
    sections.extend(
        f"  - {name}"
        for name in sorted(capabilities.permitted)
    )

    sections.append(
        f"Inheritable capabilities ({len(capabilities.inheritable)}):"
    )
    sections.extend(
        f"  - {name}"
        for name in sorted(capabilities.inheritable)
    )

    sections.append(
        f"Bounding capabilities ({len(capabilities.bounding)}):"
    )
    sections.extend(
        f"  - {name}"
        for name in sorted(capabilities.bounding)
    )

    sections.append(
        f"Ambient capabilities ({len(capabilities.ambient)}):"
    )
    sections.extend(
        f"  - {name}"
        for name in sorted(capabilities.ambient)
    )

    sections.append(
        f"Effective CAP_SYS_ADMIN: {capabilities.is_privileged}"
    )

    return "\n".join(sections)


def main() -> int:
    """Run the capabilities inspection command."""
    parser = argparse.ArgumentParser(
        description="Inspect Linux process capabilities."
    )

    parser.add_argument(
        "pid",
        type=int,
        help="Linux process ID to inspect.",
    )

    parser.add_argument(
        "--proc-root",
        default="/proc",
        help="Path to the proc filesystem (default: /proc).",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )

    args = parser.parse_args()

    try:
        capabilities = read_process_capabilities(
            pid=args.pid,
            proc_root=args.proc_root,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        parser.exit(
            status=1,
            message=f"Error: {exc}\n",
        )

    if args.json:
        print(json.dumps(capabilities.to_dict(), indent=2))
    else:
        print(format_capabilities(capabilities))

    return 0

if __name__ == "__main__":
    raise SystemExit(main())