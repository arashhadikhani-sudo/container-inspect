from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


NAMESPACE_TYPES = (
    "cgroup",
    "ipc",
    "mnt",
    "net",
    "pid",
    "pid_for_children",
    "time",
    "time_for_children",
    "user",
    "uts",
)


class NamespaceError(Exception):
    """Raised when namespace information cannot be read."""


@dataclass(frozen=True)
class Namespace:
    """Information about a single Linux namespace."""

    name: str
    inode: int
    path: Path

    def __str__(self) -> str:
        return f"{self.name}:[{self.inode}]"


class NamespaceInspector:
    """Inspect Linux namespaces belonging to a process."""

    def __init__(self, pid: int) -> None:
        if pid <= 0:
            raise ValueError("PID must be greater than 0")

        self.pid = pid
        self.proc_path = Path("/proc") / str(pid)
        self.namespace_path = self.proc_path / "ns"

    def exists(self) -> bool:
        """Return True if the process still exists."""
        return self.proc_path.exists()

    def namespaces(self) -> list[Namespace]:
        """Return all namespaces available for the process."""
        if not self.exists():
            raise NamespaceError(f"Process {self.pid} does not exist")

        result: list[Namespace] = []

        for namespace_type in NAMESPACE_TYPES:
            namespace = self._read_namespace(namespace_type)

            if namespace is not None:
                result.append(namespace)

        return result

    def _read_namespace(self, namespace_type: str) -> Namespace | None:
        """Read one namespace from /proc/<pid>/ns/."""
        path = self.namespace_path / namespace_type

        try:
            target = path.readlink()
        except FileNotFoundError:
            return None
        except PermissionError as exc:
            raise NamespaceError(
                f"Permission denied reading {path}"
            ) from exc
        except OSError as exc:
            raise NamespaceError(
                f"Could not read namespace {path}"
            ) from exc

        inode = self._parse_inode(target)

        return Namespace(
            name=namespace_type,
            inode=inode,
            path=path,
        )

    @staticmethod
    def _parse_inode(target: Path) -> int:
        """
        Parse namespace inode from a symlink target.

        Example:
            net:[4026531993]

        returns:
            4026531993
        """
        target_str = str(target)

        try:
            inode_str = target_str.split("[", 1)[1].rstrip("]")
            return int(inode_str)
        except (IndexError, ValueError) as exc:
            raise NamespaceError(
                f"Invalid namespace target: {target_str}"
            ) from exc

    def get(self, namespace_type: str) -> Namespace | None:
        """Get one specific namespace."""
        if namespace_type not in NAMESPACE_TYPES:
            raise ValueError(
                f"Unknown namespace type: {namespace_type}"
            )

        if not self.exists():
            raise NamespaceError(f"Process {self.pid} does not exist")

        return self._read_namespace(namespace_type)

    def same_namespace(
        self,
        other_pid: int,
        namespace_type: str,
    ) -> bool:
        """Check whether two processes share a namespace."""
        current = self.get(namespace_type)

        other = NamespaceInspector(other_pid).get(namespace_type)

        if current is None or other is None:
            return False

        return current.inode == other.inode



