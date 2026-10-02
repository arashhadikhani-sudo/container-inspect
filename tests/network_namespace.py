from ..src.container_inspect.network.namespace import NetworkNamespace
ns = NetworkNamespace(7111)

print(ns.exists)
print(ns.path)
print(ns.inode)