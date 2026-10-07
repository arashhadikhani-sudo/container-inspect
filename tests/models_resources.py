from ..src.container_inspect.models.resources import Resource, CPUResource, MemoryResource, PIDsResource
resource = Resource(
    cpu=CPUResource(
        quota=50000,
        period=100000,
        usage=123456789,
    ),
    memory=MemoryResource(
        limit=512 * 1024 * 1024,
        usage=128 * 1024 * 1024,
    ),
    pids=PIDsResource(
        limit=100,
        current=12,
    ),
)
print(resource.cpu.cpu_limit)
print(resource.memory.usage_percent)
print(resource.pids.available)