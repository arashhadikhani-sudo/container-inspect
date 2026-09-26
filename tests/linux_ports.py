from container_inspect.linux.ports import get_listening_ports
for port in get_listening_ports():
    print(
        port.protocol,
        port.address,
        port.state,
        port.inode,
    )