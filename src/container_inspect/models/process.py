# ./src/container_inspect/models/process.py

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Process:
    """
    Represents a Linux process.

    This model contains process information collected from
    /proc/<PID> or another process inspection source.
    """

    pid: int

    ppid: int | None = None
    name: str | None = None
    state: str | None = None

    command: list[str] = field(default_factory=list)

    uid: int | None = None
    gid: int | None = None

    executable: str | None = None
    cwd: str | None = None
    root: str | None = None

    environ: dict[str, str] = field(default_factory=dict)

    threads: int | None = None

    vm_size: int | None = None
    vm_rss: int | None = None

    start_time: int | None = None

    @property
    def cmdline(self) -> str:
        """
        Return the process command line as a string.
        """
        return " ".join(self.command)

    @property
    def is_running(self) -> bool:
        """
        Return True if the process is not in a terminal state.
        """
        return self.state not in {"Z", "X"}

    @property
    def is_zombie(self) -> bool:
        """
        Return True if the process is a zombie.
        """
        return self.state == "Z"