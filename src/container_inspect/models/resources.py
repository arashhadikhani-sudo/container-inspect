# ./src/container_inspect/models/resource.py

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class CPUResource:
    """
    CPU resource limits and usage for a container.
    """

    limit: int | None = None
    period: int | None = None
    quota: int | None = None

    shares: int | None = None
    weight: int | None = None

    usage: int | None = None
    user_usage: int | None = None
    system_usage: int | None = None

    @property
    def cpu_limit(self) -> float | None:
        """
        Return the CPU limit as a number of CPUs.

        For example:
            quota=50000
            period=100000

        gives 0.5 CPUs.
        """
        if self.quota is None or self.period is None:
            return None

        if self.quota < 0 or self.period <= 0:
            return None

        return self.quota / self.period


@dataclass(slots=True)
class MemoryResource:
    """
    Memory resource limits and usage for a container.

    Values are represented in bytes.
    """

    limit: int | None = None
    usage: int | None = None

    swap_limit: int | None = None
    swap_usage: int | None = None

    peak: int | None = None

    @property
    def available(self) -> int | None:
        """
        Return the amount of memory available under the configured limit.
        """
        if self.limit is None or self.usage is None:
            return None

        return max(self.limit - self.usage, 0)

    @property
    def usage_percent(self) -> float | None:
        """
        Return memory usage as a percentage of the configured limit.
        """
        if self.limit is None or self.usage is None:
            return None

        if self.limit <= 0:
            return None

        return (self.usage / self.limit) * 100


@dataclass(slots=True)
class PIDsResource:
    """
    PID limits and usage for a container.
    """

    limit: int | None = None
    current: int | None = None

    @property
    def available(self) -> int | None:
        """
        Return the number of additional processes that can be created.
        """
        if self.limit is None or self.current is None:
            return None

        return max(self.limit - self.current, 0)


@dataclass(slots=True)
class BlockIOResource:
    """
    Block I/O resource information.
    """

    read_bytes: int = 0
    write_bytes: int = 0

    read_operations: int = 0
    write_operations: int = 0


@dataclass(slots=True)
class NetworkResource:
    """
    Network resource statistics for a container.
    """

    rx_bytes: int = 0
    tx_bytes: int = 0

    rx_packets: int = 0
    tx_packets: int = 0

    rx_errors: int = 0
    tx_errors: int = 0

    rx_dropped: int = 0
    tx_dropped: int = 0


@dataclass(slots=True)
class Resource:
    """
    Complete resource information for a container.
    """

    cpu: CPUResource | None = None
    memory: MemoryResource | None = None
    pids: PIDsResource | None = None
    block_io: BlockIOResource | None = None
    network: NetworkResource | None = None