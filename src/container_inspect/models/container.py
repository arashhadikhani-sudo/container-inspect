from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class Container:
    """
    Data model representing a container.

    This class only stores information about a container.
    It does not inspect processes, cgroups, namespaces, mounts,
    networking, or container runtimes.

    Parameters
    ----------
    container_id:
        Unique identifier of the container.

    name:
        Optional human-readable container name.

    pid:
        PID of the container's init process.

    runtime:
        Container runtime, for example:
        runc, crun, or youki.

    status:
        Current container status, for example:
        created, running, stopped, exited, or dead.
    """

    container_id: str
    name: str | None = None
    pid: int | None = None
    runtime: str | None = None
    status: str | None = None

    def __post_init__(self) -> None:
        """Validate the container data."""

        if not isinstance(self.container_id, str):
            raise TypeError(
                "container_id must be a string"
            )

        if not self.container_id.strip():
            raise ValueError(
                "container_id cannot be empty"
            )

        if self.name is not None:
            if not isinstance(self.name, str):
                raise TypeError(
                    "name must be a string or None"
                )

            if not self.name.strip():
                self.name = None

        if self.pid is not None:
            if not isinstance(self.pid, int):
                raise TypeError(
                    "pid must be an integer or None"
                )

            if self.pid <= 0:
                raise ValueError(
                    "pid must be greater than 0"
                )

        if self.runtime is not None:
            if not isinstance(self.runtime, str):
                raise TypeError(
                    "runtime must be a string or None"
                )

            if not self.runtime.strip():
                self.runtime = None

        if self.status is not None:
            if not isinstance(self.status, str):
                raise TypeError(
                    "status must be a string or None"
                )

            if not self.status.strip():
                self.status = None

    @property
    def is_running(self) -> bool:
        """
        Return True when the container is running.
        """

        return self.status == "running"

    @property
    def is_created(self) -> bool:
        """
        Return True when the container exists but has not started.
        """

        return self.status == "created"

    @property
    def is_stopped(self) -> bool:
        """
        Return True when the container is stopped or exited.
        """

        return self.status in {
            "stopped",
            "exited",
            "dead",
        }

    @property
    def has_pid(self) -> bool:
        """
        Return True when the container has a PID.
        """

        return self.pid is not None

    @property
    def has_name(self) -> bool:
        """
        Return True when the container has a name.
        """

        return self.name is not None

    @property
    def has_runtime(self) -> bool:
        """
        Return True when a container runtime is known.
        """

        return self.runtime is not None

    @property
    def short_id(self) -> str:
        """
        Return a shortened container ID.

        The first 12 characters are used, which is a common
        representation for container IDs.
        """

        return self.container_id[:12]

    def require_pid(self) -> int:
        """
        Return the container PID.

        Raises
        ------
        RuntimeError
            If the container does not have a PID.
        """

        if self.pid is None:
            raise RuntimeError(
                f"Container {self.container_id} has no PID"
            )

        return self.pid

    def require_runtime(self) -> str:
        """
        Return the container runtime.

        Raises
        ------
        RuntimeError
            If the runtime is unknown.
        """

        if self.runtime is None:
            raise RuntimeError(
                f"Container {self.container_id} has no runtime"
            )

        return self.runtime

    def require_status(self) -> str:
        """
        Return the container status.

        Raises
        ------
        RuntimeError
            If the status is unknown.
        """

        if self.status is None:
            raise RuntimeError(
                f"Container {self.container_id} has no status"
            )

        return self.status

    def update_status(self, status: str) -> None:
        """
        Update the container status.

        Parameters
        ----------
        status:
            New container status.
        """

        if not isinstance(status, str):
            raise TypeError(
                "status must be a string"
            )

        status = status.strip()

        if not status:
            raise ValueError(
                "status cannot be empty"
            )

        self.status = status

    def update_pid(self, pid: int | None) -> None:
        """
        Update the container PID.

        Passing None removes the PID.
        """

        if pid is not None:
            if not isinstance(pid, int):
                raise TypeError(
                    "pid must be an integer or None"
                )

            if pid <= 0:
                raise ValueError(
                    "pid must be greater than 0"
                )

        self.pid = pid

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the container model to a dictionary.
        """

        return {
            "container_id": self.container_id,
            "name": self.name,
            "pid": self.pid,
            "runtime": self.runtime,
            "status": self.status,
        }

    def __repr__(self) -> str:
        """
        Return a useful representation of the container.
        """

        return (
            "Container("
            f"container_id={self.container_id!r}, "
            f"name={self.name!r}, "
            f"pid={self.pid!r}, "
            f"runtime={self.runtime!r}, "
            f"status={self.status!r}"
            ")"
        )