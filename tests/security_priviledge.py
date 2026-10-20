"""Tests for container_inspect.security.priviledge."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from container_inspect.security.priviledge import (
    ProcessIdentity,
    ProcessPrivilege,
    format_privilege_report,
    inspect_identity,
    inspect_privileges,
    parse_groups,
    parse_id_values,
    parse_integer,
    read_status_file,
    validate_pid,
)


# ---------------------------------------------------------
# Fixtures
# ---------------------------------------------------------

@pytest.fixture
def fake_proc(tmp_path: Path) -> Path:
    """Create a simulated proc filesystem for testing."""

    process_dir = tmp_path / "1234"
    process_dir.mkdir()

    status_file = process_dir / "status"

    status_file.write_text(
        "Name:\ttest-process\n"
        "Umask:\t0022\n"
        "State:\tS (sleeping)\n"
        "Pid:\t1234\n"
        "PPid:\t1\n"
        "Uid:\t1000\t1000\t1000\t1000\n"
        "Gid:\t1000\t1000\t1000\t1000\n"
        "Groups:\t10 20 30\n"
        "CapInh:\t0000000000000000\n"
        "CapPrm:\t0000000000000400\n"
        "CapEff:\t0000000000000400\n"
        "CapBnd:\t0000000000000400\n"
        "CapAmb:\t0000000000000000\n"
        "NoNewPrivs:\t1\n"
        "Seccomp:\t2\n",
        encoding="utf-8",
    )

    return tmp_path


@pytest.fixture
def root_proc(tmp_path: Path) -> Path:
    """Create a simulated process running with UID 0."""

    process_dir = tmp_path / "1"
    process_dir.mkdir()

    (process_dir / "status").write_text(
        "Name:\troot-process\n"
        "Uid:\t0\t0\t0\t0\n"
        "Gid:\t0\t0\t0\t0\n"
        "Groups:\t0\n"
        "CapInh:\t0000000000000000\n"
        "CapPrm:\t0000000000200000\n"
        "CapEff:\t0000000000200000\n"
        "CapBnd:\t0000000000200000\n"
        "CapAmb:\t0000000000000000\n"
        "NoNewPrivs:\t0\n"
        "Seccomp:\t0\n",
        encoding="utf-8",
    )

    return tmp_path


# ---------------------------------------------------------
# PID validation
# ---------------------------------------------------------

def test_validate_pid_accepts_positive_integer() -> None:
    validate_pid(1234)


@pytest.mark.parametrize("pid", [0, -1, -100])
def test_validate_pid_rejects_non_positive_values(
    pid: int,
) -> None:
    with pytest.raises(ValueError):
        validate_pid(pid)


@pytest.mark.parametrize("pid", ["1234", None, 1.5, True])
def test_validate_pid_rejects_invalid_types(
    pid: object,
) -> None:
    with pytest.raises(TypeError):
        validate_pid(pid)  # type: ignore[arg-type]


# ---------------------------------------------------------
# Status file parsing
# ---------------------------------------------------------

def test_read_status_file(fake_proc: Path) -> None:
    fields = read_status_file(
        pid=1234,
        proc_root=fake_proc,
    )

    assert fields["Name"] == "test-process"
    assert fields["Uid"] == "1000\t1000\t1000\t1000"
    assert fields["Gid"] == "1000\t1000\t1000\t1000"
    assert fields["NoNewPrivs"] == "1"
    assert fields["Seccomp"] == "2"


def test_read_status_file_ignores_unneeded_fields(
    fake_proc: Path,
) -> None:
    fields = read_status_file(1234, fake_proc)

    assert "Name" in fields
    assert "CapEff" in fields
    assert "Umask" not in fields
    assert "State" not in fields


def test_read_status_file_missing_process(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError):
        read_status_file(9999, tmp_path)


# ---------------------------------------------------------
# Integer parsing
# ---------------------------------------------------------

def test_parse_integer() -> None:
    fields = {"NoNewPrivs": "1"}

    assert parse_integer(fields, "NoNewPrivs") == 1


def test_parse_integer_missing_field() -> None:
    with pytest.raises(RuntimeError):
        parse_integer({}, "NoNewPrivs")


def test_parse_integer_invalid_value() -> None:
    fields = {"NoNewPrivs": "invalid"}

    with pytest.raises(RuntimeError):
        parse_integer(fields, "NoNewPrivs")


# ---------------------------------------------------------
# UID and GID parsing
# ---------------------------------------------------------

def test_parse_id_values() -> None:
    fields = {
        "Uid": "1000 1001 1002 1003",
    }

    assert parse_id_values(fields, "Uid") == (
        1000,
        1001,
        1002,
        1003,
    )


def test_parse_id_values_missing_field() -> None:
    with pytest.raises(RuntimeError):
        parse_id_values({}, "Uid")


def test_parse_id_values_invalid_integer() -> None:
    fields = {"Uid": "1000 abc 1000 1000"}

    with pytest.raises(RuntimeError):
        parse_id_values(fields, "Uid")


def test_parse_id_values_wrong_number_of_values() -> None:
    fields = {"Uid": "1000 1000"}

    with pytest.raises(RuntimeError):
        parse_id_values(fields, "Uid")


# ---------------------------------------------------------
# Supplementary group parsing
# ---------------------------------------------------------

def test_parse_groups() -> None:
    fields = {"Groups": "10 20 30"}

    assert parse_groups(fields) == (10, 20, 30)


def test_parse_empty_groups() -> None:
    fields = {"Groups": ""}

    assert parse_groups(fields) == ()


def test_parse_missing_groups() -> None:
    assert parse_groups({}) == ()


def test_parse_groups_invalid_value() -> None:
    fields = {"Groups": "10 abc 30"}

    with pytest.raises(RuntimeError):
        parse_groups(fields)


# ---------------------------------------------------------
# ProcessIdentity
# ---------------------------------------------------------

def test_process_identity_non_root() -> None:
    identity = ProcessIdentity(
        real_uid=1000,
        effective_uid=1000,
        saved_uid=1000,
        filesystem_uid=1000,
        real_gid=1000,
        effective_gid=1000,
        saved_gid=1000,
        filesystem_gid=1000,
        supplementary_groups=(10, 20, 30),
    )

    assert identity.is_root is False
    assert identity.has_root_identity is False


def test_process_identity_root() -> None:
    identity = ProcessIdentity(
        real_uid=0,
        effective_uid=0,
        saved_uid=0,
        filesystem_uid=0,
        real_gid=0,
        effective_gid=0,
        saved_gid=0,
        filesystem_gid=0,
        supplementary_groups=(0,),
    )

    assert identity.is_root is True
    assert identity.has_root_identity is True


def test_process_identity_saved_root_uid() -> None:
    identity = ProcessIdentity(
        real_uid=1000,
        effective_uid=1000,
        saved_uid=0,
        filesystem_uid=1000,
        real_gid=1000,
        effective_gid=1000,
        saved_gid=1000,
        filesystem_gid=1000,
        supplementary_groups=(),
    )

    assert identity.is_root is False
    assert identity.has_root_identity is True


def test_process_identity_to_dict() -> None:
    identity = ProcessIdentity(
        real_uid=1000,
        effective_uid=1000,
        saved_uid=1000,
        filesystem_uid=1000,
        real_gid=1000,
        effective_gid=1000,
        saved_gid=1000,
        filesystem_gid=1000,
        supplementary_groups=(10, 20),
    )

    result = identity.to_dict()

    assert result["real_uid"] == 1000
    assert result["supplementary_groups"] == (10, 20)
    assert result["is_root"] is False


# ---------------------------------------------------------
# Process identity inspection
# ---------------------------------------------------------

def test_inspect_identity(fake_proc: Path) -> None:
    identity = inspect_identity(
        pid=1234,
        proc_root=fake_proc,
    )

    assert identity.real_uid == 1000
    assert identity.effective_uid == 1000
    assert identity.saved_uid == 1000
    assert identity.filesystem_uid == 1000

    assert identity.real_gid == 1000
    assert identity.effective_gid == 1000

    assert identity.supplementary_groups == (10, 20, 30)
    assert identity.is_root is False


def test_inspect_root_identity(root_proc: Path) -> None:
    identity = inspect_identity(
        pid=1,
        proc_root=root_proc,
    )

    assert identity.is_root is True
    assert identity.has_root_identity is True


# ---------------------------------------------------------
# Process privilege inspection
# ---------------------------------------------------------

def test_inspect_privileges(fake_proc: Path) -> None:
    privilege = inspect_privileges(
        pid=1234,
        proc_root=fake_proc,
    )

    assert privilege.pid == 1234
    assert privilege.name == "test-process"

    assert privilege.identity.effective_uid == 1000
    assert privilege.is_root is False

    assert privilege.no_new_privs is True
    assert privilege.seccomp_mode == 2
    assert privilege.seccomp_enabled is True
    assert privilege.seccomp_description == "filter"

    assert privilege.effective_capabilities == frozenset(
        {"CAP_NET_BIND_SERVICE"}
    )

    assert privilege.permitted_capabilities == frozenset(
        {"CAP_NET_BIND_SERVICE"}
    )

    assert privilege.inheritable_capabilities == frozenset()
    assert privilege.ambient_capabilities == frozenset()

    assert privilege.has_effective_capabilities is True
    assert privilege.effective_capability_count == 1

    assert privilege.has_sys_admin is False
    assert privilege.has_net_admin is False
    assert privilege.has_net_raw is False


def test_inspect_root_privileges(root_proc: Path) -> None:
    privilege = inspect_privileges(
        pid=1,
        proc_root=root_proc,
    )

    assert privilege.is_root is True
    assert privilege.has_sys_admin is True
    assert privilege.no_new_privs is False
    assert privilege.seccomp_enabled is False


def test_inspect_privileges_invalid_pid() -> None:
    with pytest.raises(ValueError):
        inspect_privileges(0)


def test_inspect_privileges_missing_process(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError):
        inspect_privileges(9999, proc_root=tmp_path)


def test_inspect_privileges_missing_required_field(
    fake_proc: Path,
) -> None:
    status_file = fake_proc / "1234" / "status"

    content = status_file.read_text(encoding="utf-8")
    content = "\n".join(
        line
        for line in content.splitlines()
        if not line.startswith("CapEff:")
    )

    status_file.write_text(content + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="CapEff"):
        inspect_privileges(1234, proc_root=fake_proc)


def test_inspect_privileges_invalid_capability_mask(
    fake_proc: Path,
) -> None:
    status_file = fake_proc / "1234" / "status"

    content = status_file.read_text(encoding="utf-8")
    content = content.replace(
        "CapEff:\t0000000000000400",
        "CapEff:\tnot-hex",
    )

    status_file.write_text(content, encoding="utf-8")

    with pytest.raises(RuntimeError, match="CapEff"):
        inspect_privileges(1234, proc_root=fake_proc)


def test_inspect_privileges_invalid_no_new_privs(
    fake_proc: Path,
) -> None:
    status_file = fake_proc / "1234" / "status"

    content = status_file.read_text(encoding="utf-8")
    content = content.replace(
        "NoNewPrivs:\t1",
        "NoNewPrivs:\t5",
    )

    status_file.write_text(content, encoding="utf-8")

    with pytest.raises(RuntimeError, match="NoNewPrivs"):
        inspect_privileges(1234, proc_root=fake_proc)


def test_inspect_privileges_invalid_seccomp_mode(
    fake_proc: Path,
) -> None:
    status_file = fake_proc / "1234" / "status"

    content = status_file.read_text(encoding="utf-8")
    content = content.replace(
        "Seccomp:\t2",
        "Seccomp:\t5",
    )

    status_file.write_text(content, encoding="utf-8")

    with pytest.raises(RuntimeError, match="Seccomp"):
        inspect_privileges(1234, proc_root=fake_proc)


# ---------------------------------------------------------
# ProcessPrivilege serialization
# ---------------------------------------------------------

def test_privilege_to_dict(fake_proc: Path) -> None:
    privilege = inspect_privileges(
        pid=1234,
        proc_root=fake_proc,
    )

    result = privilege.to_dict()

    assert result["pid"] == 1234
    assert result["name"] == "test-process"
    assert result["is_root"] is False
    assert result["no_new_privs"] is True
    assert result["seccomp_enabled"] is True

    assert result["effective_capabilities"] == [
        "CAP_NET_BIND_SERVICE"
    ]


def test_privilege_json_serialization(
    fake_proc: Path,
) -> None:
    privilege = inspect_privileges(
        pid=1234,
        proc_root=fake_proc,
    )

    result = json.dumps(privilege.to_dict())
    decoded = json.loads(result)

    assert decoded["pid"] == 1234
    assert decoded["identity"]["effective_uid"] == 1000
    assert decoded["seccomp_description"] == "filter"


# ---------------------------------------------------------
# Human-readable report
# ---------------------------------------------------------

def test_format_privilege_report(fake_proc: Path) -> None:
    privilege = inspect_privileges(
        pid=1234,
        proc_root=fake_proc,
    )

    report = format_privilege_report(privilege)

    assert "LINUX PROCESS PRIVILEGE REPORT" in report
    assert "PID:                    1234" in report
    assert "test-process" in report
    assert "CAP_NET_BIND_SERVICE" in report
    assert "No New Privileges:      True" in report
    assert "Seccomp description:    filter" in report


def test_format_report_empty_capability_sets(
    tmp_path: Path,
) -> None:
    process_dir = tmp_path / "5678"
    process_dir.mkdir()

    (process_dir / "status").write_text(
        "Name:\tno-capabilities\n"
        "Uid:\t1000\t1000\t1000\t1000\n"
        "Gid:\t1000\t1000\t1000\t1000\n"
        "Groups:\n"
        "CapInh:\t0000000000000000\n"
        "CapPrm:\t0000000000000000\n"
        "CapEff:\t0000000000000000\n"
        "CapBnd:\t0000000000000000\n"
        "CapAmb:\t0000000000000000\n"
        "NoNewPrivs:\t0\n"
        "Seccomp:\t0\n",
        encoding="utf-8",
    )

    privilege = inspect_privileges(
        pid=5678,
        proc_root=tmp_path,
    )

    report = format_privilege_report(privilege)

    assert "(none)" in report
    assert privilege.has_effective_capabilities is False
    assert privilege.effective_capability_count == 0