from container_inspect.linux import Cgroup

cg = Cgroup(7357)

print("Version:", cg.version)
print("Proc cgroup:", cg.proc_cgroup)
print("Cgroup path:", cg.cgroup_path)
print("Cgroup directory:", cg.path)
print("Controllers:", cg.controllers)
print("Memory max:", cg.memory_max)
print("Memory current:", cg.memory_current)
print("CPU max:", cg.cpu_max)
print("PIDs max:", cg.pids_max)
print("PIDs current:", cg.pids_current)