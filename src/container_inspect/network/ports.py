from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from container_inspect.linux.ports import Port, get_ports


Protocol = Literal["tcp", "udp"]


@dataclass(slots=True)
class PortInspector:
    """
    High-level network port inspector.

    This class provides a public API for inspecting network ports
    discovered by the Linux port parser.

    Parameters
    ----------
    pid:
        Optional process ID.

        Currently this value is stored for future network namespace
        support. The actual namespace handling should be implemented
        by network.namespace rather than duplicated here.
    """

    pid: int | None = None

    def list(
        self,
        *,
        protocol: Protocol | None = None,
        listening: bool | None = None,
        local_port: int | None = None,
        local_address: str | None = None,
    ) -> list[Port]:
        """
        Return network ports matching the requested filters.

        Parameters
        ----------
        protocol:
            Filter by TCP or UDP.

        listening:
            If True, return only listening ports.
            If False, return only non-listening ports.
            If None, return all ports.

        local_port:
            Filter by local port number.

        local_address:
            Filter by local IP address.

        Returns
        -------
        list[Port]
            A list of matching ports.
        """

        ports = get_ports()

        if protocol is not None:
            ports = self._filter_protocol(
                ports,
                protocol,
            )

        if listening is not None:
            ports = self._filter_listening(
                ports,
                listening,
            )

        if local_port is not None:
            ports = self._filter_local_port(
                ports,
                local_port,
            )

        if local_address is not None:
            ports = self._filter_local_address(
                ports,
                local_address,
            )

        return ports

    @staticmethod
    def _filter_protocol(
        ports: list[Port],
        protocol: Protocol,
    ) -> list[Port]:
        """Filter ports by protocol."""

        return [
            port
            for port in ports
            if port.protocol.lower() == protocol
        ]

    @staticmethod
    def _filter_listening(
        ports: list[Port],
        listening: bool,
    ) -> list[Port]:
        """Filter ports according to their listening state."""

        return [
            port
            for port in ports
            if port.is_listening is listening
        ]

    @staticmethod
    def _filter_local_port(
        ports: list[Port],
        local_port: int,
    ) -> list[Port]:
        """Filter ports by local port number."""

        if not 0 <= local_port <= 65535:
            raise ValueError(
                "local_port must be between 0 and 65535"
            )

        return [
            port
            for port in ports
            if port.local_port == local_port
        ]

    @staticmethod
    def _filter_local_address(
        ports: list[Port],
        local_address: str,
    ) -> list[Port]:
        """Filter ports by local IP address."""

        return [
            port
            for port in ports
            if port.local_address == local_address
        ]

    def listening_ports(
        self,
        *,
        protocol: Protocol | None = None,
    ) -> list[Port]:
        """
        Return listening ports.

        This is a convenience method equivalent to:

            inspector.list(
                protocol=protocol,
                listening=True,
            )
        """

        return self.list(
            protocol=protocol,
            listening=True,
        )

    def tcp_ports(self) -> list[Port]:
        """Return all TCP ports."""

        return self.list(protocol="tcp")

    def udp_ports(self) -> list[Port]:
        """Return all UDP ports."""

        return self.list(protocol="udp")

    def tcp_listening(self) -> list[Port]:
        """Return listening TCP ports."""

        return self.list(
            protocol="tcp",
            listening=True,
        )

    def udp_listening(self) -> list[Port]:
        """Return listening UDP ports."""

        return self.list(
            protocol="udp",
            listening=True,
        )

    def find_port(self, port: int) -> list[Port]:
        """
        Find all entries using a particular local port.

        Parameters
        ----------
        port:
            Local port number.
        """

        if not 0 <= port <= 65535:
            raise ValueError(
                "port must be between 0 and 65535"
            )

        return self.list(local_port=port)