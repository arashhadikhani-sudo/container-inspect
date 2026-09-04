from abc import abstractmethod
import signal

from .base import Runtime
import subprocess

class Runc(Runtime):
    """OCI runtime implementation using runc."""

    def create(self, container_id: str) -> None:
        """Create a container."""
        subprocess.run(
                    ["runc", "create", container_id], 
                    check=True
                                )
    def start(self, container_id: str) -> None:
        """Start a container."""
        subprocess.run(
                    ["runc", "start", container_id],
                    check=True
                ) 

    def state(self, container_id: str) -> dict:
        """Return container state."""
        subprocess.run(
                     ["crun", "state", container_id],
                    check=True
        )
    def kill(self, container_id: str, signal: int) -> None:
        subprocess.run(
        ["runc", "kill", container_id, str(signal)],
        check=True,
    )
        

    @abstractmethod
    def delete(self, container_id: str) -> None:
        """Delete a container."""
        subprocess.run(
              ["runc", "kill", container_id, str(signal)],
              check=True, )