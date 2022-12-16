from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

client = '10.0.1.5'
server_1 = '10.0.1.2'
server_2 = '10.0.1.3'

client_m = '00:00:00:00:00:03'
server_1_m = '00:00:00:00:00:01'
server_2_m = '00:00:00:00:00:02'


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow1(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, idle_timeout=5,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=5,
                                    match=match, instructions=inst)

        datapath.send_msg(mod)

    # deal with PacketIn event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("Add switch %s to mac_to_port table\n", dpid)
        self.logger.info("PackIn Event\n"
                         "  dpid: %s\n"
                         "  src: %s\n"
                         "  dst: %s\n"
                         "  in_port: %s\n",
                         dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port
        self.logger.info("mac_to_port Table %s \n", self.mac_to_port)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_src=srcip,
                                            ipv4_dst=dstip, ip_proto=protocol)

                # if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    if srcip == client and dstip == server_1:
                        if server_2_m in self.mac_to_port[dpid]:
                            out_port = self.mac_to_port[dpid][server_2_m]
                        else:
                            out_port = ofproto.OFPP_FLOOD

                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip)

                        actions = [parser.OFPActionSetField(eth_dst=server_2_m),
                                   parser.OFPActionSetField(ipv4_dst=server_2),
                                   parser.OFPActionOutput(port=out_port)]

                    elif srcip == server_2 and dstip == client:
                        if client_m in self.mac_to_port[dpid]:
                            out_port = self.mac_to_port[dpid][client_m]
                        else:
                            out_port = ofproto.OFPP_FLOOD

                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip)

                        actions = [parser.OFPActionSetField(eth_src=server_1_m),
                                   parser.OFPActionSetField(ipv4_src=server_1),
                                   parser.OFPActionOutput(port=out_port)]

                    else:
                        t = pkt.get_protocol(tcp.tcp)
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_dst=dstip,
                                                ip_proto=protocol, tcp_dst=t.dst_port, )

            elif eth.ethertype == ether_types.ETH_TYPE_ARP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, in_port=in_port, eth_dst=dst, eth_src=src)

            self.add_flow1(datapath, 1, match, actions)

        data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
                                  data=data)
        datapath.send_msg(out)
