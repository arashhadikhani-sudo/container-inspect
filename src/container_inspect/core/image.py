from __future__ import annotations


class Image:
    """Represent a container image."""

    def __init__(
        self,
        name: str,
        tag: str | None = None,
        digest: str | None = None,
        architecture: str | None = None,
        os: str | None = None,
    ) -> None:
        self.name = name
        self.tag = tag
        self.digest = digest
        self.architecture = architecture
        self.os = os

    @property
    def reference(self) -> str:
        """Return the image reference."""

        if self.tag:
            return f"{self.name}:{self.tag}"

        return self.name

    def __repr__(self) -> str:
        return f"Image(reference={self.reference!r})"

