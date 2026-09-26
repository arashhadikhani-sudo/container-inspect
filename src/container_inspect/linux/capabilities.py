from __future__ import annotations

from pathlib import Path


CAPABILITY_NAMES: dict[int, str] = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}


class Capabilities:
    """Inspect Linux capabilities of a process."""

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.proc_path = Path("/proc") / str(pid)

    @property
    def status_path(self) -> Path:
        return self.proc_path / "status"

    def _read_status(self) -> dict[str, str]:
        data: dict[str, str] = {}

        with self.status_path.open("r") as file:
            for line in file:
                key, _, value = line.partition(":")
                data[key] = value.strip()

        return data

    @property
    def raw(self) -> dict[str, str]:
        status = self._read_status()

        return {
            "inheritable": status.get("CapInh", ""),
            "permitted": status.get("CapPrm", ""),
            "effective": status.get("CapEff", ""),
            "bounding": status.get("CapBnd", ""),
            "ambient": status.get("CapAmb", ""),
        }

    def _decode(self, value: str) -> list[str]:
        mask = int(value, 16)

        capabilities: list[str] = []

        for bit, name in CAPABILITY_NAMES.items():
            if mask & (1 << bit):
                capabilities.append(name)

        return capabilities

    @property
    def inheritable(self) -> list[str]:
        value = self.raw["inheritable"]

        if not value:
            return []

        return self._decode(value)

    @property
    def permitted(self) -> list[str]:
        value = self.raw["permitted"]

        if not value:
            return []

        return self._decode(value)

    @property
    def effective(self) -> list[str]:
        value = self.raw["effective"]

        if not value:
            return []

        return self._decode(value)

    @property
    def bounding(self) -> list[str]:
        value = self.raw["bounding"]

        if not value:
            return []

        return self._decode(value)

    @property
    def ambient(self) -> list[str]:
        value = self.raw["ambient"]

        if not value:
            return []

        return self._decode(value)

    def has(self, capability: str) -> bool:
        return capability in self.effective
