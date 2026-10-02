from __future__ import annotations

import os
from pathlib import Path


class NetworkNamespaceError(RuntimeError):
    """Raised when a network namespace cannot be inspected."""


class NetworkNamespace:
    """Represent a Linux network namespace."""

    def __init__(
        self,
        pid: int,
        proc_path: Path = Path("/proc"),
    ) -> None:
        if pid <= 0:
            raise ValueError("PID must be greater than zero")

        self.pid = pid
        self.proc_path = proc_path
        self.namespace_path = (
            self.proc_path
            / str(self.pid)
            / "ns"
            / "net"
        )

    @property
    def exists(self) -> bool:
        """Return True if the network namespace exists."""

        return self.namespace_path.exists()

    @property
    def inode(self) -> int:
        """
        Return the inode number of the network namespace.

        Linux identifies namespaces by their namespace inode.
        """

        if not self.exists:
            raise NetworkNamespaceError(
                f"Network namespace does not exist: "
                f"{self.namespace_path}"
            )

        try:
            return os.stat(self.namespace_path).st_ino
        except OSError as exc:
            raise NetworkNamespaceError(
                f"Unable to stat network namespace: "
                f"{self.namespace_path}"
            ) from exc

    @property
    def path(self) -> Path:
        """Return the network namespace path."""

        return self.namespace_path

    def inspect(self) -> dict[str, int | str]:
        """Return basic network namespace information."""

        if not self.exists:
            raise NetworkNamespaceError(
                f"Network namespace does not exist for PID "
                f"{self.pid}"
            )

        return {
            "pid": self.pid,
            "path": str(self.namespace_path),
            "inode": self.inode,
        }