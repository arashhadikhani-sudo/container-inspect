from container_inspect.network.routes import RouteInspector

routes = RouteInspector()

# All routes
for route in routes.list():
    print(route)

# Default route
default = routes.default()

# Routes for eth0
eth0_routes = routes.for_interface("eth0")

# Routes through a gateway
gateway_routes = routes.for_gateway("192.168.1.1")

# Check whether a default route exists
if routes.has_default_route():
    print("Default route exists")