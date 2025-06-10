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
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib import mac
from ryu.ofproto import ether
from ryu.lib.packet import packet, ethernet, ipv4, arp, icmp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
import copy

import topo

class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        
        # Initialize the topology with #ports=4
        self.topo_net = topo.Fattree(4)
        self.switch_ips = self.topo_net.switch_ips
        self.switch_forwarding_table = {}
        self.arp_cache = {}
        self.global_port_mapping = {}
        self.replay_buffer  = []
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
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
    
    # Function to get neighbors of a node
    def get_neighbors(self, src):
        connected_nodes = [link[1] for link in self.links if link[0] == src]
        return connected_nodes
    
    # Function to get the node with the smallest distance
    def get_next_node(self, unvisited_nodes, distances):
        min_dist = float('inf')
        closest_node = None
        for node in unvisited_nodes:
            if distances[node] < min_dist:
                min_dist = distances[node]
                closest_node = node
        return closest_node
    
    # Function to compute shortest path
    def compute_shortest_path(self, src, dst):
        distances = {}
        previous = {}
        unvisited_nodes = self.switches.copy()
        final_path = []
        
        # Initialize distances
        for switch in self.switches:
            distances[switch] = float('inf')
        distances[src] = 0
        while unvisited_nodes:
            curr_node = self.get_next_node(unvisited_nodes, distances)
            neighbor_nodes = self.get_neighbors(curr_node)
            for neighbor in neighbor_nodes:
                if neighbor in unvisited_nodes:
                    new_distance = distances[curr_node] + 1 # Using a weight of 1 for all nodes
                    if new_distance < distances[neighbor]:
                        distances[neighbor] = new_distance
                        previous[neighbor] = curr_node
            
            unvisited_nodes.pop(unvisited_nodes.index(curr_node))
        
        # Reconstructing the path
        start_node = dst
        while start_node != src:
            final_path.append(start_node)
            if start_node not in previous:
                self.logger.info(f'No path found from {src} to {dst}')
                return
            start_node = previous[start_node]
        final_path.append(src)
        final_path.reverse()
        self.logger.info(f'Shortest path from {src} to {dst}: {final_path}')
        return final_path
    
    def install_flows(self, route, msg, src_ip, dest_ip):
        print("Installing flows for route: ", route)
        for index, switch in enumerate(route[:-1]):
            if route[index + 1] is None:
                break
            
            for dp in self.switches_dp:
                if dp.id == switch:
                    datapath = dp
                    break
            
            next_hop = route[index + 1]
            link = None
            for link in self.links:
                if link[0] == switch and link[1] == next_hop:
                    out_port = link[2]
                    break
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.logger.info(f'Installing flow rule for switch {datapath.id}')
            
            match_ip = datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=dest_ip)
            self.add_flow(datapath, 1, match_ip, actions)
            match_arp = datapath.ofproto_parser.OFPMatch(eth_type=0x0806, arp_tpa=dest_ip)
            self.add_flow(datapath, 1, match_arp, actions)
        self.logger.info(f'Flows installed for route: {route}')
        return
        
    def handle_lev3_req(self, datapath, eth, src_ip, dest_ip, in_port, parser, msg):
        src_dpid = datapath.id
        dst_dpid = self.get_edge_switch(dest_ip)
        out_port = None
        best_route = self.compute_shortest_path(src_dpid, dst_dpid)
        next_hop = best_route[1]
        link = None
        for link in self.links:
            if link[0] == src_dpid and link[1] == next_hop:
                out_port = link[2]
                break
        self.install_flows(best_route, msg, src_ip, dest_ip)
        
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dest_ip)
        actions = [parser.OFPActionOutput(out_port)]
        self.logger.info(f'Installing routing flow rule for switch {datapath.id}')
        self.add_flow(datapath, 50, match, actions)
        out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data
                )
        datapath.send_msg(out)
        
    def get_edge_switch(self, dst_ip):
        edge_switch = None
        for switch in self.switch_ips.keys():
            switch_ip = self.switch_ips[switch]
            search_term = ".".join(dst_ip.split(".")[:3]) + ".1"
            if search_term == switch_ip:
                edge_switch = switch
                break
        
        return edge_switch
    
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
            
        if (ip_pkt or arp_pkt) and (src_dpid != dst_dpid):
            self.handle_lev3_req(datapath, eth, src_ip, dest_ip, in_port, parser, msg)
        else:
            out_port = self.switch_forwarding_table[dpid].get(dst, None)
            if not out_port:
                out_port = ofproto.OFPP_FLOOD
                
            actions = [parser.OFPActionOutput(out_port)]
            
            # If the buffer_id is not set, we need to send the data
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)