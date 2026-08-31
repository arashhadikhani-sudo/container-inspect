##container-inspect

container-inspect is a Python-based container inspection tool designed to provide detailed information about Linux containers and their underlying runtime environment.

Unlike tools that depend directly on Docker APIs, container-inspect aims to inspect containers at the Linux and OCI layers, making it useful for understanding and debugging container runtimes such as runc and crun.

Features
🔍 Container and process inspection
📦 OCI runtime configuration inspection
🐧 Linux namespace inspection
⚙️ cgroups v1/v2 information
🌐 Network namespace and interface inspection
💾 Mount and filesystem information
🔐 Linux capabilities and security information
📊 CPU, memory, and process statistics
🖥️ Human-readable terminal output
🤖 JSON/YAML output for automation
🐍 Python API for programmatic inspection
Example
container-inspect list
container-inspect inspect nginx
container-inspect inspect nginx --format json

Example output:

Container: nginx
Runtime: runc
Status: running
PID: 18421

Namespaces:
  PID: 402653xxxx
  NET: 402653xxxx
  MNT: 402653xxxx
  UTS: 402653xxxx

Resources:
  CPU: 2.3%
  Memory: 84 MB / 512 MB

Network:
  IP: 172.17.0.4
  Interfaces: eth0, lo

Security:
  Privileged: false
  Seccomp: enabled
Project goal

The goal of container-inspect is to provide a runtime-independent and developer-friendly interface for understanding what is happening inside Linux containers, while also serving as a practical tool for debugging containerized workloads.

Inspect the container. Understand the runtime. Understand Linux.

Suggested PyPI tagline

Inspect Linux containers, OCI runtimes, namespaces, cgroups, networking, and security from Python.
