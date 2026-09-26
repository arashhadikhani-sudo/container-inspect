from __future__ import annotations

from pathlib import Path


class Cgroup:
    """Inspect Linux cgroups for a process."""

    PROC_ROOT = Path("/proc")
    CGROUP_ROOT = Path("/sys/fs/cgroup")

    def __init__(self, pid: int) -> None:
        self.pid = pid

    @property
    def proc_cgroup(self) -> Path:
        """Path to /proc/<pid>/cgroup."""

        return self.PROC_ROOT / str(self.pid) / "cgroup"

    @property
    def version(self) -> int:
        """Return the cgroup version used by the process."""

        content = self.proc_cgroup.read_text()

        for line in content.splitlines():
            hierarchy, controllers, _ = line.split(":", 2)

            if hierarchy == "0" and controllers == "":
                return 2

        return 1

    @property
    def cgroup_path(self) -> str:
        """Return the process cgroup path."""

        content = self.proc_cgroup.read_text()

        for line in content.splitlines():
            hierarchy, controllers, path = line.split(":", 2)

            if hierarchy == "0" and controllers == "":
                return path

        raise RuntimeError(
            f"Could not find cgroup v2 path for PID {self.pid}"
        )

    @property
    def path(self) -> Path:
        """Return the absolute cgroup directory."""

        relative_path = self.cgroup_path.lstrip("/")

        return self.CGROUP_ROOT / relative_path

    @property
    def controllers(self) -> list[str]:
        """Return available cgroup controllers."""

        file = self.path / "cgroup.controllers"

        if not file.exists():
            return []

        return file.read_text().split()

    @property
    def memory_max(self) -> str | None:
        """Return the maximum memory limit."""

        return self._read("memory.max")

    @property
    def memory_current(self) -> str | None:
        """Return current memory usage."""

        return self._read("memory.current")

    @property
    def cpu_max(self) -> str | None:
        """Return the CPU limit."""

        return self._read("cpu.max")

    @property
    def pids_max(self) -> str | None:
        """Return the maximum number of processes."""

        return self._read("pids.max")

    @property
    def pids_current(self) -> str | None:
        """Return current number of processes."""

        return self._read("pids.current")

    def _read(self, filename: str) -> str | None:
        """Read a value from the cgroup filesystem."""

        file = self.path / filename

        if not file.exists():
            return None

        return file.read_text().strip()
