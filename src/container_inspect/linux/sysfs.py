from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


SYSFS_ROOT = Path("/sys")


class SysfsError(Exception):
    """Base exception for sysfs errors."""


class SysfsNotFoundError(SysfsError):
    """Raised when a sysfs path does not exist."""


@dataclass(slots=True)
class Sysfs:
    """Interface for reading Linux sysfs."""

    root: Path = SYSFS_ROOT

    def __post_init__(self) -> None:
        if not self.root.is_dir():
            raise SysfsNotFoundError(
                f"sysfs is not available: {self.root}"
            )

    def path(self, *parts: str) -> Path:
        """Build a path inside sysfs."""

        return self.root.joinpath(*parts)

    def exists(self, *parts: str) -> bool:
        """Check whether a sysfs path exists."""

        return self.path(*parts).exists()

    def is_file(self, *parts: str) -> bool:
        """Check whether a sysfs path is a file."""

        return self.path(*parts).is_file()

    def is_dir(self, *parts: str) -> bool:
        """Check whether a sysfs path is a directory."""

        return self.path(*parts).is_dir()

    def read(self, *parts: str) -> str:
        """Read a text file from sysfs."""

        file_path = self.path(*parts)

        try:
            return file_path.read_text(
                encoding="utf-8",
                errors="replace",
            ).strip()
        except FileNotFoundError as exc:
            raise SysfsNotFoundError(
                f"sysfs path does not exist: {file_path}"
            ) from exc
        except PermissionError as exc:
            raise SysfsError(
                f"Permission denied: {file_path}"
            ) from exc

    def read_bytes(self, *parts: str) -> bytes:
        """Read raw bytes from sysfs."""

        file_path = self.path(*parts)

        try:
            return file_path.read_bytes()
        except FileNotFoundError as exc:
            raise SysfsNotFoundError(
                f"sysfs path does not exist: {file_path}"
            ) from exc
        except PermissionError as exc:
            raise SysfsError(
                f"Permission denied: {file_path}"
            ) from exc

    def listdir(self, *parts: str) -> list[Path]:
        """List entries in a sysfs directory."""

        directory = self.path(*parts)

        try:
            return sorted(directory.iterdir())
        except FileNotFoundError as exc:
            raise SysfsNotFoundError(
                f"sysfs path does not exist: {directory}"
            ) from exc
        except PermissionError as exc:
            raise SysfsError(
                f"Permission denied: {directory}"
            ) from exc

    def read_link(self, *parts: str) -> Path:
        """Read a symbolic link from sysfs."""

        link = self.path(*parts)

        try:
            return link.resolve()
        except FileNotFoundError as exc:
            raise SysfsNotFoundError(
                f"sysfs link does not exist: {link}"
            ) from exc

    def glob(self, pattern: str) -> list[Path]:
        """Find paths inside sysfs using a glob pattern."""

        return sorted(self.root.glob(pattern))
sysfs = Sysfs()
mac = sysfs.read(
    "class",
    "net",
    "enp0s31f6",
    "address",
)

print(mac)
mtu = sysfs.read(
    "class",
    "net",
    "enp0s31f6",
    "mtu",)
print(mtu)