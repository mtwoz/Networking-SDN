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

host = '10.0.1.5'
server_1 = '10.0.1.2'
server_2 = '10.0.1.3'

proxy_m = '00:00:00:00:00:03'
server_1_m = '00:00:00:00:00:01'
server_2_m = '00:00:00:00:00:02'

class SimpleSwitch13(app_manager.RyuApp):
    # use OpenFlow 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        # use a dict to store MAC address table
        self.mac_to_port = {}

    # ofp_event.EventOFPSwitchFeatures:
    #   an event that makes function called.
    #   Every time Ryu gets a EventOFPSwitchFeatures message, this function is called.
    # CONFIG_DISPATCHER:
    #   indicates the state of the switch.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath  # Switch
        ofproto = datapath.ofproto  # OpenFLow protocol
        parser = datapath.ofproto_parser  # OpenFlow protocol parser

        # match all package
        match = parser.OFPMatch()

        # deal with all table-miss flow entries
        # ofproto.OFPP_CONTROLLER: send packages to controller
        # ofproto.OFPCML_NO_BUFFER:
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        self.logger.info("Table-miss Flow Entry\n"
                         "  datapath: %s\n"
                         "  priority: %s\n"
                         "  match: %s\n"
                         "  actions: %s\n",
                         datapath, 0, match, actions)

        # set priority=0
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        self.logger.info("Add Flow Entry\n"
                         "  datapath: %s\n"
                         "  priority: %s\n"
                         "  match: %s\n"
                         "  actions: %s\n"
                         "  buffer_id: NO_BUFFER",
                         datapath, 1, match, actions)

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
        ofproto = datapath.ofproto  # Switch OpenFlow protocol
        parser = datapath.ofproto_parser  # Switch OpenFlow protocol parser

        # instruction: define the action for packet matched
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # FlowMod function: 对 Switch 写入自定义的 Flow Entry
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, idle_timeout=5,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=5,
                                    match=match, instructions=inst)

        # send message
        datapath.send_msg(mod)

    # deal with PacketIn event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # receive packets from switch （Match 到 Table-Miss FlowEntry）
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']  # in_port in for packet in switch

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst  # dst MAC address
        src = eth.src  # src MAC address

        dpid = format(datapath.id, "d").zfill(16)  # datapath id for switch
        self.mac_to_port.setdefault(dpid, {})  # write switch MAC address into MAC address table
        self.logger.info("Add switch %s to mac_to_port table\n", dpid)
        self.logger.info("PackIn Event\n"
                         "  dpid: %s\n"
                         "  src: %s\n"
                         "  dst: %s\n"
                         "  in_port: %s\n",
                         dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        # bind src MAC address and in_port
        self.mac_to_port[dpid][src] = in_port
        self.logger.info("mac_to_port Table %s \n", self.mac_to_port)

        # if dst MAC address is in MAC address table, then just get the out_port for packet
        # otherwise use Flooding
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # define action with out_port we just got
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
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

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_dst=dstip,
                                            ip_proto=protocol, tcp_dst=t.dst_port, )

            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, in_port=in_port, eth_dst=dst, eth_src=src)

            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow1(datapath, 1, match, actions, msg.buffer_id)
                self.logger.info("Add Flow Entry\n"
                                 "  datapath: %s\n"
                                 "  priority: %s\n"
                                 "  match: %s\n"
                                 "  actions: %s\n"
                                 "  buffer_id: %s\n",
                                 datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow1(datapath, 1, match, actions)
                self.logger.info("Add Flow Entry\n"
                                 "  datapath: %s\n"
                                 "  priority: %s\n"
                                 "  match: %s\n"
                                 "  actions: %s\n"
                                 "  buffer_id: NO_BUFFER",
                                 datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
                                  data=data)
        datapath.send_msg(out)
