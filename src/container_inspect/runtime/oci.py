from pathlib import Path


class OCIBundle:
    """Represent an OCI container bundle."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    @property
    def config(self) -> Path:
        """Return the path to config.json."""
        return self.path / "config.json"