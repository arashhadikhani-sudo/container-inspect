from container_inspect.linux.namespace import NamespaceInspector


inspector = NamespaceInspector(1234)

for namespace in inspector.namespaces():
    print(namespace)