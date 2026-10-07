# ./src/container_inspect/models/network.py

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class NetworkAddress:
    """
    Represents an IP address assigned to a network interface.
    """

    address: str
    prefix_length: int
    family: str

    @property
    def cidr(self) -> str:
        """Return the address in CIDR notation."""
        return f"{self.address}/{self.prefix_length}"


@dataclass(slots=True)
class NetworkInterface:
    """
    Represents a network interface inside a container/network namespace.
    """

    name: str
    index: int | None = None
    mac_address: str | None = None
    mtu: int | None = None
    state: str | None = None
    addresses: list[NetworkAddress] = field(default_factory=list)

    @property
    def is_up(self) -> bool:
        """Return True if the interface is operationally up."""
        return self.state == "UP"


@dataclass(slots=True)
class NetworkRoute:
    """
    Represents an IP routing table entry.
    """

    destination: str
    gateway: str | None = None
    interface: str | None = None
    source: str | None = None
    metric: int | None = None
    protocol: str | None = None
    scope: str | None = None


@dataclass(slots=True)
class NetworkPort:
    """
    Represents a listening or connected network port.
    """

    protocol: str
    local_address: str
    local_port: int
    remote_address: str | None = None
    remote_port: int | None = None
    state: str | None = None
    pid: int | None = None
    process_name: str | None = None


@dataclass(slots=True)
class NetworkNamespace:
    """
    Represents a Linux network namespace.
    """

    inode: int | None = None
    path: str | None = None
    interfaces: list[NetworkInterface] = field(default_factory=list)
    routes: list[NetworkRoute] = field(default_factory=list)
    ports: list[NetworkPort] = field(default_factory=list)