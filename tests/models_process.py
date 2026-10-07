from ..src.container_inspect.models.process import Process
import os
process = Process(
    pid=os.getpid,
    ppid=os.getppid,
    name="python",
    state="S",
    command=["python", "app.py"],
    uid=1000,
    gid=1000,
    executable="/usr/bin/python",
    cwd="/home/user/app",
    root="/",
    threads=4,
)
print(process.pid)
print(process.name)
print(process.cmdline)
print(process.is_running)