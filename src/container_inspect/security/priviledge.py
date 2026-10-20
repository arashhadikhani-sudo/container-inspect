"""Linux process privilege inspection.

Inspect process identity, Linux capabilities, and privilege-related
security flags through the proc filesystem.

This module provides:
    - UID and GID inspection.
    - Supplementary group inspection.
    - Linux capability inspection.
    - NoNewPrivs inspection.
    - Seccomp mode inspection.
    - Human-readable and JSON reports.
    - Command-line interface.

This module uses the Python standard library and the existing
container_inspect.security.capabilities module.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final

from container_inspect.security.capabilities import (
    decode_capability_hex,
)


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

STATUS_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "Name",
        "Uid",
        "Gid",
        "Groups",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp",
    }
)

CAPABILITY_FIELDS: Final[dict[str, str]] = {
    "CapEff": "effective_capabilities",
    "CapPrm": "permitted_capabilities",
    "CapInh": "inheritable_capabilities",
    "CapBnd": "bounding_capabilities",
    "CapAmb": "ambient_capabilities",
}


# ---------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """Represent the user and group identity of a Linux process.

    Linux exposes four UID values and four GID values:

    - Real ID.
    - Effective ID.
    - Saved set ID.
    - Filesystem ID.

    Supplementary groups provide additional group memberships.
    """

    real_uid: int
    effective_uid: int
    saved_uid: int
    filesystem_uid: int

    real_gid: int
    effective_gid: int
    saved_gid: int
    filesystem_gid: int

    supplementary_groups: tuple[int, ...]

    @property
    def is_root(self) -> bool:
        """Return whether the effective UID is zero."""
        return self.effective_uid == 0

    @property
    def has_root_identity(self) -> bool:
        """Return whether any reported UID is zero."""
        return any(
            uid == 0
            for uid in (
                self.real_uid,
                self.effective_uid,
                self.saved_uid,
                self.filesystem_uid,
            )
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible representation."""
        return {
            **asdict(self),
            "is_root": self.is_root,
            "has_root_identity": self.has_root_identity,
        }


@dataclass(frozen=True, slots=True)
class ProcessPrivilege:
    """Represent the privilege-related state of a Linux process."""

    pid: int
    name: str
    identity: ProcessIdentity

    effective_capabilities: frozenset[str]
    permitted_capabilities: frozenset[str]
    inheritable_capabilities: frozenset[str]
    bounding_capabilities: frozenset[str]
    ambient_capabilities: frozenset[str]

    no_new_privs: bool
    seccomp_mode: int

    @property
    def is_root(self) -> bool:
        """Return whether the process has an effective UID of zero."""
        return self.identity.is_root

    @property
    def has_root_identity(self) -> bool:
        """Return whether any of the process's UIDs is zero."""
        return self.identity.has_root_identity

    @property
    def has_effective_capabilities(self) -> bool:
        """Return whether the effective capability set is nonempty."""
        return bool(self.effective_capabilities)

    @property
    def effective_capability_count(self) -> int:
        """Return the number of effective capabilities."""
        return len(self.effective_capabilities)

    @property
    def has_sys_admin(self) -> bool:
        """Check for effective CAP_SYS_ADMIN."""
        return "CAP_SYS_ADMIN" in self.effective_capabilities

    @property
    def has_net_admin(self) -> bool:
        """Check for effective CAP_NET_ADMIN."""
        return "CAP_NET_ADMIN" in self.effective_capabilities

    @property
    def has_net_raw(self) -> bool:
        """Check for effective CAP_NET_RAW."""
        return "CAP_NET_RAW" in self.effective_capabilities

    @property
    def seccomp_enabled(self) -> bool:
        """Return whether seccomp is enabled.

        Linux normally reports:
            0: disabled
            1: strict mode
            2: filter mode
        """
        return self.seccomp_mode != 0

    @property
    def seccomp_description(self) -> str:
        """Return a human-readable seccomp mode."""
        descriptions = {
            0: "disabled",
            1: "strict",
            2: "filter",
        }

        return descriptions.get(self.seccomp_mode, "unknown")

    def to_dict(self) -> dict[str, object]:
        """Convert the report to JSON-compatible data."""
        return {
            "pid": self.pid,
            "name": self.name,
            "identity": self.identity.to_dict(),
            "effective_capabilities": sorted(
                self.effective_capabilities
            ),
            "permitted_capabilities": sorted(
                self.permitted_capabilities
            ),
            "inheritable_capabilities": sorted(
                self.inheritable_capabilities
            ),
            "bounding_capabilities": sorted(
                self.bounding_capabilities
            ),
            "ambient_capabilities": sorted(
                self.ambient_capabilities
            ),
            "effective_capability_count": (
                self.effective_capability_count
            ),
            "no_new_privs": self.no_new_privs,
            "seccomp_mode": self.seccomp_mode,
            "seccomp_description": self.seccomp_description,
            "seccomp_enabled": self.seccomp_enabled,
            "is_root": self.is_root,
            "has_root_identity": self.has_root_identity,
            "has_effective_capabilities": (
                self.has_effective_capabilities
            ),
            "has_sys_admin": self.has_sys_admin,
            "has_net_admin": self.has_net_admin,
            "has_net_raw": self.has_net_raw,
        }


# ---------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------

def validate_pid(pid: int) -> None:
    """Validate a Linux process ID.

    Raises:
        TypeError: If pid is not an integer.
        ValueError: If pid is not positive.
    """
    if isinstance(pid, bool) or not isinstance(pid, int):
        raise TypeError("PID must be an integer.")

    if pid <= 0:
        raise ValueError("PID must be greater than zero.")


# ---------------------------------------------------------------------
# Proc filesystem parsing
# ---------------------------------------------------------------------

def read_status_file(
    pid: int,
    proc_root: str | Path = "/proc",
) -> dict[str, str]:
    """Read relevant fields from /proc/<PID>/status.

    Args:
        pid: Linux process ID.
        proc_root: Root of the proc filesystem.

    Returns:
        A dictionary containing the requested status fields.

    Raises:
        TypeError: If pid is not an integer.
        ValueError: If pid is not positive.
        FileNotFoundError: If the process does not exist.
        PermissionError: If access is denied.
        OSError: If another filesystem error occurs.
    """
    validate_pid(pid)

    status_path = Path(proc_root) / str(pid) / "status"
    fields: dict[str, str] = {}

    with status_path.open("r", encoding="utf-8") as status_file:
        for line in status_file:
            key, separator, value = line.partition(":")

            if not separator:
                continue

            if key in STATUS_FIELDS:
                fields[key] = value.strip()

    return fields


def parse_integer(
    fields: dict[str, str],
    field_name: str,
) -> int:
    """Parse a decimal integer from a status field."""
    value = fields.get(field_name)

    if value is None:
        raise RuntimeError(
            f"Required field {field_name!r} is missing."
        )

    try:
        return int(value, 10)
    except ValueError as exc:
        raise RuntimeError(
            f"Invalid integer in field {field_name!r}: {value!r}"
        ) from exc


def parse_id_values(
    fields: dict[str, str],
    field_name: str,
) -> tuple[int, int, int, int]:
    """Parse four UID or GID values from a status field."""
    value = fields.get(field_name)

    if value is None:
        raise RuntimeError(
            f"Required field {field_name!r} is missing."
        )

    try:
        values = tuple(
            int(item, 10)
            for item in value.split()
        )
    except ValueError as exc:
        raise RuntimeError(
            f"Invalid ID values in {field_name!r}: {value!r}"
        ) from exc

    if len(values) != 4:
        raise RuntimeError(
            f"Expected four values in {field_name!r}; "
            f"received {len(values)}."
        )

    return values  # type: ignore[return-value]


def parse_groups(
    fields: dict[str, str],
) -> tuple[int, ...]:
    """Parse supplementary group IDs."""
    value = fields.get("Groups", "")

    try:
        return tuple(
            int(item, 10)
            for item in value.split()
        )
    except ValueError as exc:
        raise RuntimeError(
            f"Invalid supplementary groups: {value!r}"
        ) from exc


# ---------------------------------------------------------------------
# Process identity inspection
# ---------------------------------------------------------------------

def inspect_identity(
    pid: int,
    proc_root: str | Path = "/proc",
) -> ProcessIdentity:
    """Inspect the UID and GID identity of a process."""
    fields = read_status_file(pid, proc_root)

    (
        real_uid,
        effective_uid,
        saved_uid,
        filesystem_uid,
    ) = parse_id_values(fields, "Uid")

    (
        real_gid,
        effective_gid,
        saved_gid,
        filesystem_gid,
    ) = parse_id_values(fields, "Gid")

    supplementary_groups = parse_groups(fields)

    return ProcessIdentity(
        real_uid=real_uid,
        effective_uid=effective_uid,
        saved_uid=saved_uid,
        filesystem_uid=filesystem_uid,
        real_gid=real_gid,
        effective_gid=effective_gid,
        saved_gid=saved_gid,
        filesystem_gid=filesystem_gid,
        supplementary_groups=supplementary_groups,
    )


# ---------------------------------------------------------------------
# Privilege inspection
# ---------------------------------------------------------------------

def inspect_privileges(
    pid: int,
    proc_root: str | Path = "/proc",
) -> ProcessPrivilege:
    """Inspect the privilege-related state of a Linux process.

    Reads identity, capabilities, NoNewPrivs, and Seccomp from
    /proc/<PID>/status.

    Args:
        pid: Linux process ID.
        proc_root: Root of the proc filesystem.

    Returns:
        A ProcessPrivilege object.

    Raises:
        TypeError: If pid is not an integer.
        ValueError: If pid is not positive.
        FileNotFoundError: If the process does not exist.
        PermissionError: If access is denied.
        RuntimeError: If required fields are missing or malformed.
        OSError: If another filesystem error occurs.
    """
    validate_pid(pid)

    fields = read_status_file(pid, proc_root)

    required_fields = {
        "Name",
        "Uid",
        "Gid",
        "CapEff",
        "CapPrm",
        "CapInh",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp",
    }

    missing_fields = required_fields - fields.keys()

    if missing_fields:
        missing = ", ".join(sorted(missing_fields))

        raise RuntimeError(
            f"Missing required fields for PID {pid}: {missing}"
        )

    identity = ProcessIdentity(
        real_uid=parse_id_values(fields, "Uid")[0],
        effective_uid=parse_id_values(fields, "Uid")[1],
        saved_uid=parse_id_values(fields, "Uid")[2],
        filesystem_uid=parse_id_values(fields, "Uid")[3],
        real_gid=parse_id_values(fields, "Gid")[0],
        effective_gid=parse_id_values(fields, "Gid")[1],
        saved_gid=parse_id_values(fields, "Gid")[2],
        filesystem_gid=parse_id_values(fields, "Gid")[3],
        supplementary_groups=parse_groups(fields),
    )

    decoded_capabilities: dict[str, frozenset[str]] = {}

    for proc_field, attribute_name in CAPABILITY_FIELDS.items():
        try:
            decoded_capabilities[attribute_name] = (
                decode_capability_hex(fields[proc_field])
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"Invalid {proc_field} for PID {pid}: "
                f"{fields[proc_field]!r}"
            ) from exc

    no_new_privs_value = parse_integer(fields, "NoNewPrivs")
    seccomp_mode = parse_integer(fields, "Seccomp")

    if no_new_privs_value not in (0, 1):
        raise RuntimeError(
            f"Invalid NoNewPrivs value: {no_new_privs_value}"
        )

    if seccomp_mode not in (0, 1, 2):
        raise RuntimeError(
            f"Unexpected Seccomp mode: {seccomp_mode}"
        )

    return ProcessPrivilege(
        pid=pid,
        name=fields["Name"],
        identity=identity,
        effective_capabilities=decoded_capabilities[
            "effective_capabilities"
        ],
        permitted_capabilities=decoded_capabilities[
            "permitted_capabilities"
        ],
        inheritable_capabilities=decoded_capabilities[
            "inheritable_capabilities"
        ],
        bounding_capabilities=decoded_capabilities[
            "bounding_capabilities"
        ],
        ambient_capabilities=decoded_capabilities[
            "ambient_capabilities"
        ],
        no_new_privs=bool(no_new_privs_value),
        seccomp_mode=seccomp_mode,
    )


# ---------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------

def format_privilege_report(
    privilege: ProcessPrivilege,
) -> str:
    """Format process privilege information for terminal output."""
    identity = privilege.identity

    lines = [
        "=" * 64,
        "LINUX PROCESS PRIVILEGE REPORT",
        "=" * 64,
        f"PID:                    {privilege.pid}",
        f"Name:                   {privilege.name}",
        "",
        "IDENTITY",
        "-" * 64,
        f"Real UID:               {identity.real_uid}",
        f"Effective UID:          {identity.effective_uid}",
        f"Saved UID:              {identity.saved_uid}",
        f"Filesystem UID:         {identity.filesystem_uid}",
        f"Real GID:               {identity.real_gid}",
        f"Effective GID:          {identity.effective_gid}",
        f"Saved GID:              {identity.saved_gid}",
        f"Filesystem GID:         {identity.filesystem_gid}",
        "Supplementary groups:   "
        + ", ".join(map(str, identity.supplementary_groups)),
        f"Effective root:         {privilege.is_root}",
        "",
        "SECURITY FLAGS",
        "-" * 64,
        f"No New Privileges:      {privilege.no_new_privs}",
        f"Seccomp mode:           {privilege.seccomp_mode}",
        f"Seccomp description:    {privilege.seccomp_description}",
        f"Seccomp enabled:        {privilege.seccomp_enabled}",
        "",
        "CAPABILITIES",
        "-" * 64,
    ]

    capability_sets = (
        ("Effective", privilege.effective_capabilities),
        ("Permitted", privilege.permitted_capabilities),
        ("Inheritable", privilege.inheritable_capabilities),
        ("Bounding", privilege.bounding_capabilities),
        ("Ambient", privilege.ambient_capabilities),
    )

    for label, capabilities in capability_sets:
        lines.append(f"{label} ({len(capabilities)}):")

        if capabilities:
            lines.extend(
                f"  - {name}"
                for name in sorted(capabilities)
            )
        else:
            lines.append("  (none)")

        lines.append("")

    lines.extend(
        [
            "PRIVILEGE CHECKS",
            "-" * 64,
            f"Effective CAP_SYS_ADMIN: {privilege.has_sys_admin}",
            f"Effective CAP_NET_ADMIN: {privilege.has_net_admin}",
            f"Effective CAP_NET_RAW:   {privilege.has_net_raw}",
            "=" * 64,
        ]
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------

def main() -> int:
    """Run the privilege inspection CLI."""
    parser = argparse.ArgumentParser(
        prog="container-inspect-privilege",
        description="Inspect Linux process privileges.",
    )

    parser.add_argument(
        "pid",
        type=int,
        help="Linux process ID to inspect.",
    )

    parser.add_argument(
        "--proc-root",
        default="/proc",
        help="Proc filesystem root. Default: /proc.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the report as JSON.",
    )

    args = parser.parse_args()

    try:
        privilege = inspect_privileges(
            pid=args.pid,
            proc_root=args.proc_root,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        parser.exit(
            status=1,
            message=f"Error: {exc}\n",
        )

    if args.json:
        print(
            json.dumps(
                privilege.to_dict(),
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(format_privilege_report(privilege))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())