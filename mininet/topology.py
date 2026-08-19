#!/usr/bin/env python3
"""
Mininet topology for the Dynamic Firewall DDoS experiment.

Topology:
    h1 = Server / target
    h2 = SYN Flood attacker
    h3 = UDP Flood attacker
    h4 = Normal traffic host
    s1 = OpenFlow switch
    c0 = Ryu controller

The topology is intended to match the experimental layout used
in the portfolio evidence. Adjust IPs/interfaces only if your
actual lab configuration differs.
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def create_topology():
    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    info("*** Adding Ryu controller\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633
    )

    info("*** Adding switch\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    info("*** Adding hosts\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24")  # Server / target
    h2 = net.addHost("h2", ip="10.0.0.2/24")  # SYN Flood attacker
    h3 = net.addHost("h3", ip="10.0.0.3/24")  # UDP Flood attacker
    h4 = net.addHost("h4", ip="10.0.0.4/24")  # Normal traffic

    info("*** Creating links\n")
    for host in (h1, h2, h3, h4):
        net.addLink(host, s1)

    info("*** Starting network\n")
    net.build()
    c0.start()
    s1.start([c0])

    info("*** Network ready\n")
    info("    h1 = Server / target      10.0.0.1\n")
    info("    h2 = SYN Flood attacker  10.0.0.2\n")
    info("    h3 = UDP Flood attacker  10.0.0.3\n")
    info("    h4 = Normal traffic      10.0.0.4\n")
    info("    s1 = OpenFlow 1.3 switch\n")
    info("    c0 = Ryu controller      127.0.0.1:6633\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    create_topology()
