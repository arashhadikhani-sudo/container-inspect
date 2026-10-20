# Container Inspect — Architecture

## 1. Overview

Container Inspect is a Python package for inspecting Linux containers,
processes, networking, resources, and security configurations.

The project uses Linux kernel interfaces such as `/proc` and `/sys`,
along with container runtime interfaces, to collect system information.

### Goals

- Provide detailed information about Linux containers.
- Inspect processes, namespaces, and cgroups.
- Inspect network interfaces, routes, and ports.
- Inspect Linux capabilities, privileges, and Seccomp settings.
- Support multiple container runtimes.
- Produce structured, machine-readable results.
- Keep the architecture modular and testable.
- Perform read-only inspection by default.

---

## 2. Architecture Overview

```text
                    User
                     |
                     v
              +--------------+
              |     CLI      |
              |     cli/     |
              +--------------+
                     |
                     v
              +--------------+
              |     Core     |
              |     core/    |
              +--------------+
                     |
          +----------+----------+
          |          |          |
          v          v          v
     +---------+ +---------+ +---------+
     | Runtime | |  Linux  | | Security|
     | Adapters| | Inspect.| | Inspect.|
     +---------+ +---------+ +---------+
          |          |          |
          v          v          v
     Runtime CLI   /proc      Capabilities
     and APIs      /sys       Seccomp
          |          |          |
          +----------+----------+
                     |
                     v
              +--------------+
              |    Models    |
              |   models/    |
              +--------------+
                     |
                     v
             Structured Results
               JSON / Python