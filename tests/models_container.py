from container_inspect.models.container import Container


container = Container(
    container_id="de519fc5f6a3",
    name="angry_gates",
    pid="2033",
    runtime="",
    status="running",
)

print(container.container_id)
print(container.name)
print(container.pid)
print(container.runtime)
print(container.status)
print(container.is_running)
print(container.has_pid)
print(container.short_id)
print(container.to_dict())