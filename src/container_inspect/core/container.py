from __future__ import annotations

from pathlib import Path


class Container:
    def __init__(
        self,
        container_id: str,
        name: str | None = None,
        pid: int | None = None,
        runtime: str | None = None,
        status: str | None = None,
    ) -> None:
        self.container_id = container_id
        self.name = name
        self.pid = pid
        self.runtime = runtime
        self.status = status

    def require_pid(self) -> int:
        if self.pid is None:
            raise RuntimeError(
                f"Container {self.container_id} does not have a PID"
            )

        return self.pid

    @property
    def proc_path(self) -> Path:
        return Path("/proc") / str(self.require_pid())

    @property
    def namespace_path(self) -> Path:
        return self.proc_path / "ns"
