from __future__ import annotations


class ContainerInspectError(Exception):
    """Base exception for container-inspect."""

    pass


class ProcessNotFoundError(ContainerInspectError):
    """Raised when the requested process does not exist."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        super().__init__(f"Process with PID {pid} was not found.")


class PermissionDeniedError(ContainerInspectError):
    """Raised when access to process information is denied."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Permission denied while accessing: {path}")


class InvalidPIDError(ContainerInspectError):
    """Raised when an invalid PID is provided."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        super().__init__(f"Invalid PID: {pid}")


class ProcFilesystemError(ContainerInspectError):
    """Raised when /proc cannot be accessed."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Unable to access proc filesystem path: {path}")