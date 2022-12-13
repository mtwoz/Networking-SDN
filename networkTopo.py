from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.term import makeTerm


def myTopo():
    net = Mininet(topo=None, autoSetMacs=True, build=False, ipBase='10.0.1.0/24')

    # controller
    c1 = net.addController('c1', RemoteController)

    # hosts
    # h1: client
    # h2: server 1
    # h3: server 2
    h1 = net.addHost('h1', cls=Host, defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, defaultRoute=None)

    # switch
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, failMode='secure')

    # links
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    # network build
    net.build()

    # set MAC addresses
    h1.setMAC(intf="h1-eth0", mac="00:00:00:00:00:03")
    h2.setMAC(intf="h2-eth0", mac="00:00:00:00:00:01")
    h3.setMAC(intf="h3-eth0", mac="00:00:00:00:00:02")

    # set IP addresses
    h1.setIP(intf="h1-eth0", ip='10.0.1.5/24')
    h2.setIP(intf="h2-eth0", ip='10.0.1.2/24')
    h3.setIP(intf="h3-eth0", ip='10.0.1.3/24')

    # network start
    net.start()

    # start xterms
    net.terms += makeTerm(c1)
    net.terms += makeTerm(s1)
    net.terms += makeTerm(h1)
    net.terms += makeTerm(h2)
    net.terms += makeTerm(h3)

    # CLI mode running
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    myTopo()
