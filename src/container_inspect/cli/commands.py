"""
CLI commands for container-inspect.

This module defines the command-line interface and dispatches
commands to the appropriate inspection components.
"""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    """Build and return the main argument parser."""

    parser = argparse.ArgumentParser(
        prog="container-inspect",
        description=(
            "Inspect Linux containers from the OCI and Linux kernel layers."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version="container-inspect 0.1.0",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        metavar="COMMAND",
    )

    # inspect
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect a container.",
    )

    inspect_parser.add_argument(
        "container",
        help="Container name or ID.",
    )

    inspect_parser.add_argument(
        "--json",
        action="store_true",
        help="Output information as JSON.",
    )

    # namespaces
    namespace_parser = subparsers.add_parser(
        "namespace",
        aliases=["ns"],
        help="Inspect container namespaces.",
    )

    namespace_parser.add_argument(
        "container",
        help="Container name or ID.",
    )

    # cgroups
    cgroup_parser = subparsers.add_parser(
        "cgroup",
        aliases=["cg"],
        help="Inspect container cgroups.",
    )

    cgroup_parser.add_argument(
        "container",
        help="Container name or ID.",
    )

    # network
    network_parser = subparsers.add_parser(
        "network",
        aliases=["net"],
        help="Inspect container networking.",
    )

    network_parser.add_argument(
        "container",
        help="Container name or ID.",
    )

    # processes
    process_parser = subparsers.add_parser(
        "processes",
        aliases=["ps"],
        help="Show processes running inside a container.",
    )

    process_parser.add_argument(
        "container",
        help="Container name or ID.",
    )

    # mounts
    mount_parser = subparsers.add_parser(
        "mounts",
        help="Inspect container mounts.",
    )

    mount_parser.add_argument(
        "container",
        help="Container name or ID.",
    )

    # security
    security_parser = subparsers.add_parser(
        "security",
        help="Inspect container security configuration.",
    )

    security_parser.add_argument(
        "container",
        help="Container name or ID.",
    )

    # list
    subparsers.add_parser(
        "list",
        aliases=["ls"],
        help="List running containers.",
    )

    return parser


def command_list() -> int:
    """List containers.

    This is intentionally a placeholder. The actual container discovery
    implementation should live outside this CLI module.
    """

    print("Container listing is not implemented yet.")
    return 0


def command_inspect(container: str, json_output: bool = False) -> int:
    """Inspect a container."""

    print(f"Inspecting container: {container}")

    if json_output:
        print("{}")

    return 0


def command_namespace(container: str) -> int:
    """Inspect container namespaces."""

    print(f"Inspecting namespaces: {container}")
    return 0


def command_cgroup(container: str) -> int:
    """Inspect container cgroups."""

    print(f"Inspecting cgroups: {container}")
    return 0


def command_network(container: str) -> int:
    """Inspect container networking."""

    print(f"Inspecting network: {container}")
    return 0


def command_processes(container: str) -> int:
    """Show container processes."""

    print(f"Processes in container: {container}")
    return 0


def command_mounts(container: str) -> int:
    """Inspect container mounts."""

    print(f"Mounts for container: {container}")
    return 0


def command_security(container: str) -> int:
    """Inspect container security configuration."""

    print(f"Security information: {container}")
    return 0


def run(argv: list[str] | None = None) -> int:
    """Parse arguments and execute the requested command."""

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command in ("list", "ls"):
        return command_list()

    if args.command == "inspect":
        return command_inspect(
            args.container,
            json_output=args.json,
        )

    if args.command in ("namespace", "ns"):
        return command_namespace(args.container)

    if args.command in ("cgroup", "cg"):
        return command_cgroup(args.container)

    if args.command in ("network", "net"):
        return command_network(args.container)

    if args.command in ("processes", "ps"):
        return command_processes(args.container)

    if args.command == "mounts":
        return command_mounts(args.container)

    if args.command == "security":
        return command_security(args.container)

    parser.print_help()
    return 0


def main() -> None:
    """CLI entry point."""

    try:
        raise SystemExit(run())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
