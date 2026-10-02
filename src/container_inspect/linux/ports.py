from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import socket
import struct


PROC_NET = Path("/proc/net")


@dataclass(frozen=True, slots=True)
class Port:
    """A listening or bound network port."""

    protocol: str
    local_address: str
    local_port: int
    remote_address: str | None = None
    remote_port: int | None = None
    state: str | None = None
    inode: int | None = None

    @property
    def address(self) -> str:
        """Return address:port representation."""
        if ":" in self.local_address:
            return f"[{self.local_address}]:{self.local_port}"

        return f"{self.local_address}:{self.local_port}"


TCP_STATES: dict[str, str] = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}


def _decode_ipv4(hex_address: str) -> str:
    """Decode an IPv4 address from /proc/net format."""
    raw = bytes.fromhex(hex_address)

    # /proc/net/tcp stores IPv4 addresses in little-endian form.
    return socket.inet_ntoa(raw[::-1])


def _decode_ipv6(hex_address: str) -> str:
    """Decode an IPv6 address from /proc/net format."""
    raw = bytes.fromhex(hex_address)

    # Linux represents IPv6 addresses in four little-endian
    # 32-bit words in /proc/net/tcp6.
    address = b"".join(
        struct.pack("<I", struct.unpack("<I", raw[i:i + 4])[0])
        for i in range(0, 16, 4)
    )

    return socket.inet_ntop(socket.AF_INET6, address)


def _decode_endpoint(
    endpoint: str,
    ipv6: bool = False,
) -> tuple[str, int]:
    """Decode an address:port field from /proc/net."""
    address, port = endpoint.split(":", 1)

    if ipv6:
        decoded_address = _decode_ipv6(address)
    else:
        decoded_address = _decode_ipv4(address)

    return decoded_address, int(port, 16)


def _parse_file(
    path: Path,
    protocol: str,
    ipv6: bool = False,
) -> list[Port]:
    """Parse a /proc/net/{tcp,udp,tcp6,udp6} file."""
    ports: list[Port] = []

    if not path.exists():
        return ports

    try:
        lines = path.read_text().splitlines()
    except PermissionError:
        return ports

    # First line contains column names.
    for line in lines[1:]:
        fields = line.split()

        if len(fields) < 10:
            continue

        local_address, local_port = _decode_endpoint(
            fields[1],
            ipv6=ipv6,
        )

        remote_address, remote_port = _decode_endpoint(
            fields[2],
            ipv6=ipv6,
        )

        state = fields[3]

        try:
            inode = int(fields[9])
        except ValueError:
            inode = None

        ports.append(
            Port(
                protocol=protocol,
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=remote_port,
                state=TCP_STATES.get(state, state)
                if protocol == "tcp"
                else None,
                inode=inode,
            )
        )

    return ports


def get_tcp_ports() -> list[Port]:
    """Return IPv4 and IPv6 TCP sockets."""
    return [
        *_parse_file(PROC_NET / "tcp", "tcp"),
        *_parse_file(PROC_NET / "tcp6", "tcp", ipv6=True),
    ]


def get_udp_ports() -> list[Port]:
    """Return IPv4 and IPv6 UDP sockets."""
    return [
        *_parse_file(PROC_NET / "udp", "udp"),
        *_parse_file(PROC_NET / "udp6", "udp", ipv6=True),
    ]


def get_ports(
    protocol: str | None = None,
    listening_only: bool = False,
) -> list[Port]:
    """
    Return network sockets.

    Args:
        protocol:
            "tcp", "udp", or None for both.

        listening_only:
            For TCP, return only LISTEN sockets.
            UDP sockets are returned because UDP has no TCP-style
            LISTEN state.
    """
    if protocol is not None:
        protocol = protocol.lower()

        if protocol not in {"tcp", "udp"}:
            raise ValueError(
                f"Unsupported protocol: {protocol!r}. "
                "Expected 'tcp', 'udp', or None."
            )

    if protocol == "tcp":
        ports = get_tcp_ports()
    elif protocol == "udp":
        ports = get_udp_ports()
    else:
        ports = [
            *get_tcp_ports(),
            *get_udp_ports(),
        ]

    if listening_only:
        ports = [
            port
            for port in ports
            if port.protocol != "tcp"
            or port.state == "LISTEN"
        ]

    return sorted(
        ports,
        key=lambda port: (
            port.protocol,
            port.local_port,
            port.local_address,
        ),
    )


def get_listening_ports() -> list[Port]:
    """Return TCP listening sockets and UDP sockets."""
    return get_ports(listening_only=True)


def get_ports_for_pid(
    pid: int,
    protocol: str | None = None,
    listening_only: bool = False,
) -> list[Port]:
    """
    Return sockets belonging to a process.

    This works by inspecting the process' socket file descriptors
    and matching their inode numbers against /proc/net entries.
    """
    if pid <= 0:
        raise ValueError("pid must be greater than zero")

    fd_path = Path("/proc") / str(pid) / "fd"

    if not fd_path.exists():
        raise FileNotFoundError(
            f"Process {pid} does not exist."
        )

    socket_inodes: set[int] = set()

    try:
        for fd in fd_path.iterdir():
            try:
                target = fd.resolve()
            except (FileNotFoundError, PermissionError):
                continue

            target_str = str(target)

            if target_str.startswith("socket:[") and target_str.endswith("]"):
                inode_str = target_str[8:-1]

                try:
                    socket_inodes.add(int(inode_str))
                except ValueError:
                    continue

    except PermissionError:
        return []

    ports = get_ports(
        protocol=protocol,
        listening_only=listening_only,
    )

    return [
        port
        for port in ports
        if port.inode in socket_inodes
    ]


__all__ = [
    "Port",
    "get_ports",
    "get_tcp_ports",
    "get_udp_ports",
    "get_listening_ports",
    "get_ports_for_pid",
]
for port in get_listening_ports():
    print(
        port.protocol,
        port.address,
        port.state,
        port.inode,
    )
