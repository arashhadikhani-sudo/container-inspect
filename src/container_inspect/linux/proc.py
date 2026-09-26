from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PROC_ROOT = Path("/proc")


class ProcError(Exception):
    """Base exception for /proc inspection errors."""


class ProcessNotFoundError(ProcError):
    """Raised when the requested process does not exist."""


@dataclass(slots=True)
class ProcProcess:
    """Inspect a Linux process through procfs."""

    pid: int
    proc_root: Path = PROC_ROOT

    def __post_init__(self) -> None:
        if self.pid <= 0:
            raise ValueError("PID must be greater than zero")

        if not self.path.is_dir():
            raise ProcessNotFoundError(
                f"Process {self.pid} does not exist: {self.path}"
            )

    @property
    def path(self) -> Path:
        """Return the /proc directory for this process."""

        return self.proc_root / str(self.pid)

    @property
    def cmdline(self) -> list[str]:
        """Return the process command line."""

        data = self._read_bytes("cmdline")

        if not data:
            return []

        return [
            argument.decode(errors="replace")
            for argument in data.split(b"\0")
            if argument
        ]

    @property
    def command(self) -> str:
        """Return the process command name."""

        return self._read_text("comm").strip()

    @property
    def executable_path(self) -> str:
        """Return the process executable path."""

        try:
            return str((self.path / "exe").resolve())
        except OSError:
            return ""

    @property
    def cwd(self) -> str:
        """Return the process current working directory."""

        try:
            return str((self.path / "cwd").resolve())
        except OSError:
            return ""

    @property
    def root(self) -> str:
        """Return the process root filesystem."""

        try:
            return str((self.path / "root").resolve())
        except OSError:
            return ""

    @property
    def environ(self) -> dict[str, str]:
        """Return the process environment."""

        data = self._read_bytes("environ")

        if not data:
            return {}

        environment: dict[str, str] = {}

        for item in data.split(b"\0"):
            if not item or b"=" not in item:
                continue

            key, value = item.split(b"=", 1)

            environment[key.decode(errors="replace")] = (
                value.decode(errors="replace")
            )

        return environment

    @property
    def status(self) -> dict[str, str]:
        """Parse /proc/<PID>/status."""

        data = self._read_text("status")

        result: dict[str, str] = {}

        for line in data.splitlines():
            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()

        return result

    @property
    def uid(self) -> int | None:
        """Return the real UID."""

        value = self.status.get("Uid")

        if not value:
            return None

        try:
            return int(value.split()[0])
        except (ValueError, IndexError):
            return None

    @property
    def gid(self) -> int | None:
        """Return the real GID."""

        value = self.status.get("Gid")

        if not value:
            return None

        try:
            return int(value.split()[0])
        except (ValueError, IndexError):
            return None

    @property
    def state(self) -> str | None:
        """Return the process state."""

        value = self.status.get("State")

        if not value:
            return None

        return value.split()[0]

    @property
    def threads(self) -> int | None:
        """Return the number of threads."""

        value = self.status.get("Threads")

        if not value:
            return None

        try:
            return int(value)
        except ValueError:
            return None

    @property
    def fd(self) -> list[Path]:
        """Return open file descriptors."""

        fd_path = self.path / "fd"

        try:
            return sorted(
                fd_path.iterdir(),
                key=lambda path: int(path.name),
            )
        except (FileNotFoundError, PermissionError):
            return []

    @property
    def fd_count(self) -> int:
        """Return the number of open file descriptors."""

        return len(self.fd)

    @property
    def maps(self) -> list[str]:
        """Return memory mappings."""

        data = self._read_text("maps")

        if not data:
            return []

        return data.splitlines()

    @property
    def mountinfo(self) -> list[str]:
        """Return mount information."""

        data = self._read_text("mountinfo")

        if not data:
            return []

        return data.splitlines()

    @property
    def mounts(self) -> list[str]:
        """Return mounted filesystems."""

        data = self._read_text("mounts")

        if not data:
            return []

        return data.splitlines()

    def exists(self) -> bool:
        """Check whether the process still exists."""

        return self.path.is_dir()

    def _read_text(self, name: str) -> str:
        """Read a text file from procfs."""

        try:
            return (self.path / name).read_text(
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as exc:
            raise ProcessNotFoundError(
                f"Process {self.pid} disappeared"
            ) from exc
        except PermissionError as exc:
            raise ProcError(
                f"Permission denied reading /proc/{self.pid}/{name}"
            ) from exc

    def _read_bytes(self, name: str) -> bytes:
        """Read a binary file from procfs."""

        try:
            return (self.path / name).read_bytes()
        except FileNotFoundError as exc:
            raise ProcessNotFoundError(
                f"Process {self.pid} disappeared"
            ) from exc
        except PermissionError as exc:
            raise ProcError(
                f"Permission denied reading /proc/{self.pid}/{name}"
            ) from exc
