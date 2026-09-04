from .base import Runtime
import subprocess

class Crun(Runtime):
    """OCI runtime implementation using crun."""

    def create(self, container_id: str) -> None:
        """Create a container."""
        subprocess.run(
            ["crun", "create", container_id], 
            check=True
                        )

    def start(self, container_id: str) -> None:
        """Start a container."""
        subprocess.run(
            ["crun", "start", container_id],
            check=True
        ) 
            
        

    def state(self, container_id: str) -> dict:
        """Return container state."""
        subprocess.run(
             ["crun", "status", container_id],
            check=True
        )
    def kill(self, container_id: str, signal: int) -> None:
        """Send a signal to a container."""
        subprocess.run(
                     ["crun", "kill", container_id],
                    check=True
                )

    def delete(self, container_id: str) -> None:
        """Delete a container."""
        subprocess.run(
            ["youki" "delete "] , check=True
        )
