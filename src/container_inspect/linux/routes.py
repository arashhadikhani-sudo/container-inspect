from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path


PROC_NET_ROUTE = Path("/proc/net/route")


class RouteError(Exception):
    """Base exception for routing-table errors."""


@dataclass(slots=True, frozen=True)
class Route:
    """Represent an IPv4 route."""

    interface: str
    destination: IPv4Address
    gateway: IPv4Address
    mask: IPv4Address
    flags: int
    metric: int
    ref_count: int
    use: int
    mtu: int
    window: int
    irtt: int

    @property
    def is_default(self) -> bool:
        """Return True if this is the default route."""

        return int(self.destination) == 0 and int(self.mask) == 0

    @property
    def is_gateway(self) -> bool:
        """Return True if the route uses a gateway."""

        return int(self.gateway) != 0


class RouteTable:
    """Parse the Linux IPv4 routing table."""

    def __init__(
        self,
        proc_file: Path = PROC_NET_ROUTE,
    ) -> None:
        self.proc_file = proc_file

    def routes(self) -> list[Route]:
        """Return all IPv4 routes."""

        try:
            content = self.proc_file.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as exc:
            raise RouteError(
                f"Routing table not found: {self.proc_file}"
            ) from exc
        except PermissionError as exc:
            raise RouteError(
                f"Permission denied reading: {self.proc_file}"
            ) from exc

        lines = content.splitlines()

        if not lines:
            return []

        result: list[Route] = []

        # First line is the header.
        for line in lines[1:]:
            if not line.strip():
                continue

            route = self._parse_line(line)

            if route is not None:
                result.append(route)

        return result

    def default_route(self) -> Route | None:
        """Return the default route, if one exists."""

        for route in self.routes():
            if route.is_default:
                return route

        return None

    def _parse_line(self, line: str) -> Route | None:
        """Parse one /proc/net/route line."""

        fields = line.split()

        if len(fields) < 11:
            return None

        try:
            interface = fields[0]

            destination = self._hex_to_ipv4(fields[1])
            gateway = self._hex_to_ipv4(fields[2])

            flags = int(fields[3], 16)
            ref_count = int(fields[4])
            use = int(fields[5])
            metric = int(fields[6])

            mask = self._hex_to_ipv4(fields[7])

            mtu = int(fields[8])
            window = int(fields[9])
            irtt = int(fields[10])

        except (ValueError, IndexError) as exc:
            raise RouteError(
                f"Invalid route entry: {line!r}"
            ) from exc

        return Route(
            interface=interface,
            destination=destination,
            gateway=gateway,
            mask=mask,
            flags=flags,
            metric=metric,
            ref_count=ref_count,
            use=use,
            mtu=mtu,
            window=window,
            irtt=irtt,
        )

    @staticmethod
    def _hex_to_ipv4(value: str) -> IPv4Address:
        """Convert Linux /proc/net/route hexadecimal IPv4 to an address."""

        number = int(value, 16)

        octets = [
            (number >> 0) & 0xFF,
            (number >> 8) & 0xFF,
            (number >> 16) & 0xFF,
            (number >> 24) & 0xFF,
        ]

        return IPv4Address(".".join(map(str, octets)))
