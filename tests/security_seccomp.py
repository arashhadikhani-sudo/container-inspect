from container_inspect.security.seccomp import (
    inspect_seccomp,
    format_seccomp_report,
)

info = inspect_seccomp(24728)

print(info.mode_name)
print(info.enabled)
print(info.no_new_privs)

print(format_seccomp_report(info))