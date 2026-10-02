# src/container_inspect/network/routes.py

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from container_inspect.linux.routes import Route, get_routes

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass(slots=True)
class RouteInspector:
    """
    High-level network route inspector.

    Parameters
    ----------
    pid:
        Optional process ID whose network namespace should eventually
        be inspected.

        Network namespace switching belongs in network.namespace.py.
        This class only provides the high-level route API.
    """

    pid: int | None = None

    def list(
        self,
        *,
        interface: str | None = None,
        destination: str | None = None,
        gateway: str | None = None,
    ) -> list[Route]:
        """
        Return network routes matching the supplied filters.

        Parameters
        ----------
        interface:
            Filter routes by network interface.

        destination:
            Filter routes by destination network.

        gateway:
            Filter routes by gateway address.
        """

        routes = list(get_routes())

        if interface is not None:
            routes = self._filter_interface(
                routes,
                interface,
            )

        if destination is not None:
            routes = self._filter_destination(
                routes,
                destination,
            )

        if gateway is not None:
            routes = self._filter_gateway(
                routes,
                gateway,
            )

        return routes

    @staticmethod
    def _filter_interface(
        routes: Iterable[Route],
        interface: str,
    ) -> list[Route]:
        """Return routes using the specified interface."""

        return [
            route
            for route in routes
            if route.interface == interface
        ]

    @staticmethod
    def _filter_destination(
        routes: Iterable[Route],
        destination: str,
    ) -> list[Route]:
        """Return routes matching the destination."""

        return [
            route
            for route in routes
            if route.destination == destination
        ]

    @staticmethod
    def _filter_gateway(
        routes: Iterable[Route],
        gateway: str,
    ) -> list[Route]:
        """Return routes using the specified gateway."""

        return [
            route
            for route in routes
            if route.gateway == gateway
        ]

    def default(self) -> Route | None:
        """
        Return the default IPv4 route.

        A default route normally has destination:

            0.0.0.0/0

        Returns None when no default route exists.
        """

        routes = self.list()

        for route in routes:
            if route.destination in {
                "0.0.0.0/0",
                "default",
            }:
                return route

        return None

    def for_interface(
        self,
        interface: str,
    ) -> list[Route]:
        """
        Return all routes belonging to an interface.
        """

        return self.list(interface=interface)

    def for_gateway(
        self,
        gateway: str,
    ) -> list[Route]:
        """
        Return all routes using a gateway.
        """

        return self.list(gateway=gateway)

    def has_default_route(self) -> bool:
        """Return True if a default route exists."""

        return self.default() is not None

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