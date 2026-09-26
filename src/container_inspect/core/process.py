from pathlib import Path


class Process:
    """Represent a Linux process using the /proc filesystem."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.proc_path = Path("/proc") / str(pid)

    @property
    def exists(self) -> bool:
        """Return True if the process exists."""
        return self.proc_path.exists()

    @property
    def cmdline(self) -> list[str]:
        """Return the process command line as a list of arguments."""
        cmdline_path = self.proc_path / "cmdline"

        content = cmdline_path.read_bytes()

        return [
            argument.decode()
            for argument in content.split(b"\0")
            if argument
        ]

    @property
    def executable(self) -> Path:
        """Return the path to the process executable."""
        return self.proc_path / "exe"

    @property
    def status(self) -> dict[str, str]:
        """Return information from /proc/<pid>/status."""
        status_path = self.proc_path / "status"

        result: dict[str, str] = {}

        for line in status_path.read_text().splitlines():
            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            result[key] = value.strip()

        return result

    @property
    def parent_pid(self) -> int:
        """Return the parent process ID."""
        status = self.status
        return int(status["PPid"])
      



