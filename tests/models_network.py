from ..src.container_inspect.models.network import NetworkInterface, NetworkAddress
NetworkInterface(
    name="eth0",
    index=2,
    mac_address="02:42:ac:11:00:02",
    mtu=1500,
    state="UP",
    addresses=[
        NetworkAddress(
            address="172.17.0.2",
            prefix_length=16,
            family="inet",
        )
    ],
)