from container_inspect.linux.sysfs import Sysfs


sysfs = Sysfs()
mac = sysfs.read(
    "class",
    "net",
    "enp0s31f6",
    "address",
)

print(mac)

mtu = sysfs.read(
    "class",
    "net",
    "enp0s31f6",
    "mtu"
)
print(mtu)