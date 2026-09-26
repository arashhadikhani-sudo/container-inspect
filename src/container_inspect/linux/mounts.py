from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True, frozen=True)
class Mount:
    mount_id: int
    parent_id: int
    major: int
    minor: int
    root: str
    mount_point: str
    options: list[str]
    optional_fields: list[str]
    filesystem: str
    mount_source: str
    super_options: list[str]


class MountInspector:
    """
    Inspect Linux mounts through /proc/<PID>/mountinfo.
    """

    def __init__(self, pid: int | None = None) -> None:
        self.pid = pid if pid is not None else 1
        self.proc_path = Path("/proc") / str(self.pid)

    @property
    def mountinfo_path(self) -> Path:
        return self.proc_path / "mountinfo"

    def exists(self) -> bool:
        return self.mountinfo_path.exists()

    def read(self) -> str:
        if not self.exists():
            raise FileNotFoundError(
                f"mountinfo not found for PID {self.pid}: "
                f"{self.mountinfo_path}"
            )

        return self.mountinfo_path.read_text(encoding="utf-8")

    def mounts(self) -> list[Mount]:
        mounts: list[Mount] = []

        for line in self.read().splitlines():
            if not line.strip():
                continue

            mounts.append(self._parse_line(line))

        return mounts

    def _parse_line(self, line: str) -> Mount:
        """
        Parse one line from /proc/<PID>/mountinfo.

        Format:

        mount ID
        parent ID
        major:minor
        root
        mount point
        mount options
        optional fields...
        -
        filesystem
        mount source
        super options
        """

        separator = line.split(" - ", maxsplit=1)

        if len(separator) != 2:
            raise ValueError(f"Invalid mountinfo line: {line!r}")

        pre_separator, post_separator = separator

        pre = pre_separator.split()
        post = post_separator.split()

        if len(pre) < 6:
            raise ValueError(f"Invalid mountinfo prefix: {line!r}")

        if len(post) < 3:
            raise ValueError(f"Invalid mountinfo suffix: {line!r}")

        mount_id = int(pre[0])
        parent_id = int(pre[1])

        major, minor = self._parse_device_number(pre[2])

        root = self._unescape(pre[3])
        mount_point = self._unescape(pre[4])

        options = self._split_options(pre[5])

        optional_fields = [
            self._unescape(field)
            for field in pre[6:]
        ]

        filesystem = post[0]
        mount_source = self._unescape(post[1])
        super_options = self._split_options(post[2])

        return Mount(
            mount_id=mount_id,
            parent_id=parent_id,
            major=major,
            minor=minor,
            root=root,
            mount_point=mount_point,
            options=options,
            optional_fields=optional_fields,
            filesystem=filesystem,
            mount_source=mount_source,
            super_options=super_options,
        )

    @staticmethod
    def _parse_device_number(value: str) -> tuple[int, int]:
        try:
            major, minor = value.split(":", maxsplit=1)
            return int(major), int(minor)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"Invalid device number: {value!r}"
            ) from exc

    @staticmethod
    def _split_options(value: str) -> list[str]:
        if not value:
            return []

        return value.split(",")

    @staticmethod
    def _unescape(value: str) -> str:
        """
        Decode octal escaping used by mountinfo.

        Examples:

            \\040 -> space
            \\011 -> tab
            \\134 -> backslash
        """

        replacements = {
            r"\040": " ",
            r"\011": "\t",
            r"\012": "\n",
            r"\134": "\\",
        }

        for escaped, character in replacements.items():
            value = value.replace(escaped, character)

        return value
