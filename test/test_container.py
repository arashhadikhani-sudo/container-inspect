from container_inspect.core.container import Container

container = Container(
    container_id="test123",
    pid=1234,
)

print(container.proc_path)
print(container.namespace_path)