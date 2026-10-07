from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class NetworkInterface:
    """Information about a Linux network interface."""

    name: str
    ifindex: int | None = None
    mac_address: str | None = None
    mtu: int | None = None
    operstate: str | None = None
    rx_bytes: int | None = None
    rx_packets: int | None = None
    tx_bytes: int | None = None
    tx_packets: int | None = None


class InterfaceError(RuntimeError):
    """Raised when an interface cannot be inspected."""


class InterfaceInspector:
    """Inspect Linux network interfaces through sysfs."""

    def __init__(
        self,
        sysfs_path: Path = Path("/sys/class/net"),
    ) -> None:
        self.sysfs_path = sysfs_path

    def list_interfaces(self) -> list[NetworkInterface]:
        """Return all network interfaces available in sysfs."""

        if not self.sysfs_path.exists():
            raise InterfaceError(
                f"Network interface path does not exist: {self.sysfs_path}"
            )

        interfaces: list[NetworkInterface] = []

        for interface_path in sorted(self.sysfs_path.iterdir()):
            if not interface_path.is_dir():
                continue

            try:
                interfaces.append(
                    self.inspect(interface_path.name)
                )
            except (OSError, ValueError):
                continue

        return interfaces

    def inspect(self, name: str) -> NetworkInterface:
        """Inspect a single network interface."""

        interface_path = self.sysfs_path / name

        if not interface_path.exists():
            raise InterfaceError(
                f"Network interface does not exist: {name}"
            )

        return NetworkInterface(
            name=name,
            ifindex=self._read_int(interface_path / "ifindex"),
            mac_address=self._read_text(
                interface_path / "address"
            ),
            mtu=self._read_int(interface_path / "mtu"),
            operstate=self._read_text(
                interface_path / "operstate"
            ),
            rx_bytes=self._read_stat(
                interface_path, "rx_bytes"
            ),
            rx_packets=self._read_stat(
                interface_path, "rx_packets"
            ),
            tx_bytes=self._read_stat(
                interface_path, "tx_bytes"
            ),
            tx_packets=self._read_stat(
                interface_path, "tx_packets"
            ),
        )

    @staticmethod
    def _read_text(path: Path) -> str | None:
        try:
            return path.read_text().strip()
        except (OSError, UnicodeError):
            return None

    @staticmethod
    def _read_int(path: Path) -> int | None:
        value = InterfaceInspector._read_text(path)

        if value is None:
            return None

        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def _read_stat(
        interface_path: Path,
        name: str,
    ) -> int | None:
        return InterfaceInspector._read_int(
            interface_path / "statistics" / name
        )