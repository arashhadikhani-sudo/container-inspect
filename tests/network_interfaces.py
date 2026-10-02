from container_inspect.network.interfaces import InterfaceInspector

inspector = InterfaceInspector()

for interface in inspector.list_interfaces():
    print(interface)
interface = inspector.inspect("lo")

print(interface.name)
print(interface.mac_address)
print(interface.mtu)
print(interface.operstate)