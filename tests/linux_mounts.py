from container_inspect.linux.routes import RouteTable


table = RouteTable()

for route in table.routes():
    print(route.interface)
    print(route.destination)
    print(route.gateway)
    print(route.mask)
    print(route.metric)
    print()