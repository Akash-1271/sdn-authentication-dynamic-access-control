
import subprocess

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


ROOT_IF = "ctrlroot0"
SWITCH_IF = "ctrlovs0"
ROOT_IP = "10.0.0.254/24"


class AuthenticationTopology(Topo):
    def build(self):
        h1 = self.addHost("h1", ip="10.0.0.1/24")
        h2 = self.addHost("h2", ip="10.0.0.2/24")
        h_auth = self.addHost("h_auth", ip="10.0.0.3/24")
        h_srv = self.addHost("h_srv", ip="10.0.0.4/24")

        s1 = self.addSwitch(
            "s1",
            protocols="OpenFlow13",
            failMode="secure",
        )

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h_auth, s1)
        self.addLink(h_srv, s1)


def setup_controller_link():
    """Connect Ubuntu's network namespace to the Mininet switch."""
    # Refuse to delete an interface owned by an earlier or unrelated run.
    if subprocess.run(["ip", "link", "show", ROOT_IF],
                      stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0:
        raise RuntimeError(f"{ROOT_IF} already exists; inspect it before cleanup")

    subprocess.run(
        [
            "ip", "link", "add", ROOT_IF,
            "type", "veth",
            "peer", "name", SWITCH_IF,
        ],
        check=True,
    )

    try:
        subprocess.run(
            ["ip", "addr", "add", ROOT_IP, "dev", ROOT_IF],
            check=True,
        )

        subprocess.run(
            ["ip", "link", "set", ROOT_IF, "up"],
            check=True,
        )

        subprocess.run(
            ["ovs-vsctl", "--may-exist", "add-port", "s1", SWITCH_IF],
            check=True,
        )

        subprocess.run(
            ["ip", "link", "set", SWITCH_IF, "up"],
            check=True,
        )

    except Exception:
        subprocess.run(
            ["ip", "link", "delete", ROOT_IF],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        raise

    info(f"*** Controller control-link address: {ROOT_IP}\n")


def run():
    bridge = subprocess.run(["ovs-vsctl", "br-exists", "s1"])
    if bridge.returncode == 0:
        raise RuntimeError("s1 already exists; inspect it before starting a new topology")
    if bridge.returncode != 2:
        raise RuntimeError("Cannot query Open vSwitch; check permissions/service")
    for name in (ROOT_IF, SWITCH_IF):
        if subprocess.run(["ip", "link", "show", name],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0:
            raise RuntimeError(f"{name} already exists; inspect before cleanup")
    topo = AuthenticationTopology()
    control_link_created = False

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=True,
        build=False,
    )

    net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653,
    )

    try:
        info("*** Building Mininet network\n")
        net.build()
        net.start()

        setup_controller_link()
        control_link_created = True

        info("*** Topology running\n")
        info("*** Hosts: h1, h2, h_auth, h_srv\n")
        info("*** Entering Mininet CLI; type exit to stop\n")
        CLI(net)

    finally:
        net.stop()
        if control_link_created:
            subprocess.run(["ip", "link", "delete", ROOT_IF],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    setLogLevel("info")
    run()
