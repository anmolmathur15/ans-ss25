"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import topo


class FTRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)
        
        # Initialize the topology with #ports=4
        self.topo_net = topo.Fattree(4)
        self.switch_ips = self.topo_net.switch_ips
        self.switch_forwarding_table = {}
        self.arp_cache = {}
        self.global_port_mapping = {}
        self.replay_buffer  = []
        self.switch_prefixes = {}
        self.switch_suffixes = {}
        self.switches = []
        self.links = []
        self.k = 4  # Number of ports per switch
        self.switches_dp = []

    # Topology discovery
    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]
    @set_ev_cls(events)
    def get_topology_data(self, ev):
        # Switches and links in the network
        all_switches = get_switch(self, None)
        all_links = get_link(self, None)
        
        self.global_port_mapping = {}
        self.switches = [switch.dp.id for switch in all_switches]
        self.switches_dp = [switch.dp for switch in all_switches]
        self.links = [(link.src.dpid, link.dst.dpid, link.src.port_no, link.dst.port_no) for link in all_links]
        
        self.logger.info("Switches: %s", len(self.switches))
        self.logger.info("Links: %s", len(self.links))
        for src, dst, src_port, dst_port in self.links:
            if not self.global_port_mapping.get(src):
                self.global_port_mapping[src] = []
            if not self.global_port_mapping.get(dst):
                self.global_port_mapping[dst] = []
                
            if (src_port, dst) not in self.global_port_mapping[src]:
                self.global_port_mapping[src].append((src_port, dst))
            if (dst_port, src) not in self.global_port_mapping[dst]:
                self.global_port_mapping[dst].append((dst_port, src))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install entry-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        
    def get_edge_switch(self, dst_ip):
        edge_switch = None
        for switch in self.switch_ips.keys():
            switch_ip = self.switch_ips[switch]
            search_term = ".".join(dst_ip.split(".")[:3]) + ".1"
            if search_term == switch_ip:
                edge_switch = switch
                break
        
        return edge_switch
    
    def get_prefix(self, ip, subnet_mask):
        prefix_length = int(subnet_mask / 8)
        if prefix_length < 0 or prefix_length > 4:
            self.logger.error("Invalid prefix length: %s", prefix_length)
            return None
        ip_parts = ip.split('.')
        prefix_parts = ip_parts[:prefix_length]
        return '.'.join(prefix_parts) + '.0' * (4 - prefix_length)
    
    def get_suffix(self, ip, subnet_mask):
        suffix_length = int(subnet_mask / 8)
        if suffix_length <= 0 or suffix_length > 4:
            self.logger.error("Invalid suffix length: %s", suffix_length)
            return None
        ip_parts = ip.split('.')
        suffix_parts = ip_parts[-suffix_length:]
        return '.'.join(suffix_parts) + '.0' * (4 - suffix_length)
    
    def type_of_traffic(self, src_dpid, dest_ip):
        switch_ip = self.switch_ips.get(src_dpid, None)
        switch_prefix_24 = self.get_prefix(switch_ip, 24)
        dst_prefix_24 = self.get_prefix(dest_ip, 24)
        switch_prefix_16 = self.get_prefix(switch_ip, 16)
        dst_prefix_16 = self.get_prefix(dest_ip, 16)
        
        if switch_prefix_24 == dst_prefix_24:
            return "switch"
        elif switch_prefix_16 == dst_prefix_16:
            return "intra_pod"
        else:
            return "inter_pod"
        
    def type_of_switch(self, src_dpid):
        switch_ip = self.switch_ips.get(src_dpid, None)
        if switch_ip is not None:
            split_ip = switch_ip.split('.')
            if (int(split_ip[1]) < self.k) and (int(split_ip[2]) < (self.k // 2)):
                return "edge"
            elif (int(split_ip[1]) < self.k) and (int(split_ip[2]) >= (self.k // 2)):
                return "aggregation"
            else:
                return "core"
        
    def handle_edge_switch(self, datapath, eth, src_ip, dest_ip, in_port, parser, msg, traffic_type):
        self.logger.info("Handling edge switch for src_ip: %s, dest_ip: %s", src_ip, dest_ip)
        actions = []
        if traffic_type == "switch":
            self.logger.info("Handling within switch traffic")
            out_port = self.switch_forwarding_table[datapath.id].get(eth.dst, None)
            if out_port:
                actions.append(parser.OFPActionOutput(out_port))
                match_ip = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dest_ip)
                match_arp = parser.OFPMatch(eth_type=0x0806, arp_tpa=dest_ip)
                self.add_flow(datapath, 50, match_ip, actions)
                self.add_flow(datapath, 50, match_arp, actions)
            else:
                out_port = datapath.ofproto.OFPP_FLOOD
                actions.append(parser.OFPActionOutput(out_port))
        else:
            self.logger.info("Handling outside switch traffic")
            ports = [port[0] for port in self.global_port_mapping[datapath.id]]
            dst_host_id = int(dest_ip.split('.')[-1])
            out_port = ports[dst_host_id % len(ports)]
            actions.append(parser.OFPActionOutput(out_port))
            match_ip = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dest_ip)
            match_arp = parser.OFPMatch(eth_type=0x0806, arp_tpa=dest_ip)
            self.add_flow(datapath, 10, match_ip, actions)
            self.add_flow(datapath, 10, match_arp, actions)
        
        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def handle_aggregation_switch(self, datapath, eth, src_ip, dest_ip, in_port, parser, msg, traffic_type):
        self.logger.info("Handling aggregation switch for src_ip: %s, dest_ip: %s", src_ip, dest_ip)
        actions = []
        switch_ports = self.global_port_mapping.get(datapath.id, [])
            
        if traffic_type == "intra_pod":
            out_port = None
            dest_prefix_24 = self.get_prefix(dest_ip, 24)
            for port, dpid in switch_ports:
                if self.type_of_switch(dpid) != "core": # Not Uplink port
                    connecting_switch_ip = self.switch_ips.get(dpid, None)
                    if dest_prefix_24 == self.get_prefix(connecting_switch_ip, 24):
                        out_port = port
                        break
            actions.append(parser.OFPActionOutput(out_port))
            match_ip = parser.OFPMatch(eth_type=0x0800, ipv4_dst=(dest_ip, '255.255.255.0')) # Match subnet of edge switch
            match_arp = parser.OFPMatch(eth_type=0x0806, arp_tpa=(dest_ip, '255.255.255.0'))
            self.add_flow(datapath, 50, match_ip, actions)
            self.add_flow(datapath, 50, match_arp, actions)
        else:
            host_id = int(dest_ip.split('.')[-1])
            switch_id = int(dest_ip.split('.')[-2])
            # out_port = (host_id - 2 + switch_id) % (self.k // 2) + self.k // 2
            upstream_ports = []
            for port, dpid in switch_ports:
                if self.type_of_switch(dpid) == "core": # Not Uplink port
                    upstream_ports.append(port)
            out_port = upstream_ports[host_id % len(upstream_ports)]
            actions.append(parser.OFPActionOutput(out_port))
            match_ip = parser.OFPMatch(eth_type=0x0800, ipv4_dst=(dest_ip, '0.0.0.255')) # Match by host ID
            match_arp = parser.OFPMatch(eth_type=0x0806, arp_tpa=(dest_ip, '0.0.0.255'))
            self.add_flow(datapath, 10, match_ip, actions)
            self.add_flow(datapath, 10, match_arp, actions)
        
        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def handle_core_switch(self, datapath, eth, src_ip, dest_ip, in_port, parser, msg, traffic_type):
        dest_prefix_16 = self.get_prefix(dest_ip, 16)
        switch_ports = self.global_port_mapping.get(datapath.id, [])
        out_port = None
        for port, dpid in switch_ports:
                pod_switch_ip = self.switch_ips.get(dpid, None)
                if dest_prefix_16 == self.get_prefix(pod_switch_ip, 16):
                    out_port = port
                    break
        actions = [parser.OFPActionOutput(out_port)]
        match_ip = parser.OFPMatch(eth_type=0x0800, ipv4_dst=(dest_ip, '255.255.0.0')) # Match pod number
        match_arp = parser.OFPMatch(eth_type=0x0806, arp_tpa=(dest_ip, '255.255.0.0'))
        self.add_flow(datapath, 50, match_ip, actions)
        self.add_flow(datapath, 50, match_arp, actions)
        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
            
    def handle_lev3_req(self, datapath, eth, src_ip, dest_ip, in_port, parser, msg):
        src_dpid = datapath.id
        switch_type = self.type_of_switch(src_dpid)
        traffic_type = self.type_of_traffic(src_dpid, dest_ip)
        if switch_type == "edge":
            self.handle_edge_switch(datapath, eth, src_ip, dest_ip, in_port, parser, msg, traffic_type)
        elif switch_type == "aggregation":
            self.handle_aggregation_switch(datapath, eth, src_ip, dest_ip, in_port, parser, msg, traffic_type)
        else:
            self.handle_core_switch(datapath, eth, src_ip, dest_ip, in_port, parser, msg, traffic_type)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # TODO: handle new packets at the controller
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        in_port = msg.match['in_port']
        dst = eth.dst
        src = eth.src
        
        # Filter out LLDP packets
        if eth.ethertype == 35020 or eth.ethertype == 34525:
            return
        
        # Learn MAC address
        if dpid not in self.switch_forwarding_table:
            self.switch_forwarding_table[dpid] = {}
        if src not in self.switch_forwarding_table[dpid]:
            self.switch_forwarding_table[dpid][src] = in_port
            
        if ip_pkt:
            src_ip = ip_pkt.src
            dest_ip = ip_pkt.dst
        elif arp_pkt:
            src_ip = arp_pkt.src_ip
            dest_ip = arp_pkt.dst_ip
            
        src_dpid = datapath.id
        dst_dpid = self.get_edge_switch(dest_ip)
            
        if (ip_pkt or arp_pkt):
            self.handle_lev3_req(datapath, eth, src_ip, dest_ip, in_port, parser, msg)
        else:
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            
            # If the buffer_id is not set, we need to send the data
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)