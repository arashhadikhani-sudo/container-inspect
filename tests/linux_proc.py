from .linux_proc import ProcProcess
import os 
process = ProcProcess(os.getpid())
print(process.command)
print(process.cmdline)
print(process.executable_path)
print(process.cwd)
print(process.root)
print(process.uid)
print(process.gid)
print(process.state)
print(process.threads)
