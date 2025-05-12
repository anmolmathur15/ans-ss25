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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp
from ryu.ofproto import ether
from ryu.lib.packet import in_proto
from ryu.lib import mac
import ipaddress


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        # Switch forwarding table
        self.switch_forwarding_table = {}
        self.arp_cache = {}
        self.router_forwarding_table = {}
        self.replay_buffer = []
        self.ext_subnet = ipaddress.ip_network("192.168.1.0/24")
        self.ser_subnet = ipaddress.ip_network("10.0.2.0/24")
        self.router_gateways = ["10.0.1.1", "10.0.2.1", "192.168.1.1"]
        
        # Routing table
        self.routing_table = {
            "10.0.1.0/24": {
                "mac": "00:00:00:00:01:01",
                "port": 1,
                "gateway": "10.0.1.1"
            },
            "10.0.2.0/24": {
                "mac": "00:00:00:00:01:02",
                "port": 2,
                "gateway": "10.0.2.1"
            },
            "192.168.1.0/24": {
                "mac": "00:00:00:00:01:03",
                "port": 3,
                "gateway": "192.168.1.1"
            }
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
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
        
    def send_packet_lev2(self, datapath, dpid, eth, msg, ofproto, parser):
        in_port = msg.match['in_port']
        dst = eth.dst
        src = eth.src
        
        # Learn MAC address of interface
        if dpid not in self.switch_forwarding_table:
            self.switch_forwarding_table[dpid] = {}
            
        self.switch_forwarding_table[dpid][src] = in_port
        
        if dst in self.switch_forwarding_table[dpid]:
            out_port = self.switch_forwarding_table[dpid][dst]
        else:
            self.logger.info(f'No entry found in the forwarding table of switch {dpid} flooding all ports')
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Installing flow rule
        if out_port != ofproto.OFPP_FLOOD:
            self.logger.info(f'Installing flow rule for switch {dpid}')
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def handle_arp_req(self, datapath, eth, arp_pkt, in_port):
        # Learn the ip to mac address mapping
        self.arp_cache[arp_pkt.src_ip] = arp_pkt.src_mac
        
        dest_ip = arp_pkt.dst_ip
        
        matching_ip = False
        interface_info = {}
        for subnet, route_info in self.routing_table.items():
            if ipaddress.ip_address(dest_ip) == ipaddress.ip_address(route_info['gateway']):
                matching_ip = True
                interface_info = route_info
                break
                
        if matching_ip:
            interface_ip = interface_info['gateway']
            self.logger.info(f'ARP request received for router interface {interface_ip}')
            arp_resp = packet.Packet()
            arp_resp.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                                    dst=eth.src, src=interface_info['mac']))
            arp_resp.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                    src_mac=interface_info['mac'], src_ip=interface_ip,
                                    dst_mac=arp_pkt.src_mac,
                                    dst_ip=arp_pkt.src_ip))
            
            arp_resp.serialize()
            actions = []
            actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
            parser = datapath.ofproto_parser  
            ofproto = datapath.ofproto
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_resp)
            datapath.send_msg(out)
            
    def send_arp_req(self, src, dest_ip, datapath, out_port):
        arp_req = packet.Packet()
        dest_mac = mac.BROADCAST_STR
        arp_req.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                dst=dest_mac, src=src['mac']))
        arp_req.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
                                src_mac=src['mac'], src_ip=src['ip'],
                                dst_mac=dest_mac,
                                dst_ip=dest_ip))
        
        arp_req.serialize()
        actions = []
        actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
        parser = datapath.ofproto_parser  
        ofproto = datapath.ofproto
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_req)
        self.logger.info(f'Initiating ARP request for IP {dest_ip}')
        datapath.send_msg(out)
            
    def reply_to_icmp_echo(self, datapath, in_port, parser, eth, ip_pkt, icmp_pkt):
        self.logger.info("ICMP_ECHO_REQUEST received for router interface, sending reply")
        echo_reply = icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY,
            code=0,
            csum=0,
            data=icmp_pkt.data
        )

        reply_eth = ethernet.ethernet(
            ethertype=eth.ethertype,
            dst=eth.src,
            src=eth.dst
        )
        reply_ip = ipv4.ipv4(
            dst=ip_pkt.src,
            src=ip_pkt.dst,
            proto=ip_pkt.proto
        )

        reply_pkt = packet.Packet()
        reply_pkt.add_protocol(reply_eth)
        reply_pkt.add_protocol(reply_ip)
        reply_pkt.add_protocol(echo_reply)
        reply_pkt.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=reply_pkt.data
        )
        datapath.send_msg(out)
        return
    

    def handle_ip_req(self, datapath, eth, ip_pkt, icmp_pkt, in_port, parser):
        src_ip = ip_pkt.src
        dest_ip = ip_pkt.dst
        
        # Find the best matching route
        matching_routes = []
        for subnet, route_info in self.routing_table.items():
            if ipaddress.ip_address(dest_ip) in ipaddress.ip_network(subnet):
                matching_routes.append((subnet, route_info))
            
        # Longest prefix match
        if not matching_routes:
            self.logger.info(f'Unable to find route for destination IP {dest_ip} dropping packet')
            return
        
        best_route = max(matching_routes, key=lambda x: ipaddress.ip_network(x[0]).prefixlen)
        out_port = best_route[1]['port']
        
        try:
            subnet = ipaddress.ip_network(best_route[0])
            if (
                ipaddress.ip_address(src_ip) in subnet and
                ipaddress.ip_address(dest_ip) == ipaddress.ip_address(best_route[1]['gateway']) and
                icmp_pkt
            ):

                self.logger.info('Host pinging own gateway, allowing packet')
                dest_mac = best_route[1]['mac']
                self.reply_to_icmp_echo(datapath, in_port, parser, eth, ip_pkt, icmp_pkt)
                return
                
            elif dest_ip in self.router_gateways:
                self.logger.info('Host pinging external gateway, dropping packet')
                return
            else:
                dest_mac = self.arp_cache[dest_ip]
        except (KeyError, IndexError):
            self.logger.info(f'Unable to find MAC address of {dest_ip} in ARP cache, generating ARP request')
            src = {
                "ip": best_route[1]['gateway'],
                "mac": best_route[1]['mac']
            }
            self.send_arp_req(src, dest_ip, datapath, out_port)
            self.replay_buffer.append({
                "datapath": datapath,
                "eth": eth,
                "ip_pkt": ip_pkt,
                "icmp_pkt": icmp_pkt,
                "in_port": in_port,
                "parser": parser
            })
            return
            

        updated_eth = ethernet.ethernet(ethertype=eth.ethertype, dst=dest_mac, src=best_route[1]['mac'])
        
        actions = [
            parser.OFPActionSetField(eth_dst=dest_mac),
            parser.OFPActionSetField(eth_src=best_route[1]['mac']),
            parser.OFPActionOutput(out_port)
        ]
        

        new_pkt = packet.Packet()
        new_pkt.add_protocol(updated_eth)
        new_pkt.add_protocol(ip_pkt)
        
        if icmp_pkt:
            new_pkt.add_protocol(icmp_pkt)
            
        new_pkt.serialize()
        self.logger.info(f'Forwarded packet to next hop with IP {dest_ip}')

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=new_pkt.data)
        datapath.send_msg(out)
        
    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Your controller implementation should start here
        dpid = datapath.id
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        in_port = msg.match['in_port']
        if dpid == 3 and arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST:
                self.logger.info(f'ARP request received at device {dpid}')
                self.handle_arp_req(datapath, eth, arp_pkt, in_port)
            
            elif arp_pkt.opcode == arp.ARP_REPLY:
                self.logger.info(f'ARP reply message received at device {dpid}')
                self.arp_cache[arp_pkt.src_ip] = arp_pkt.src_mac
                if self.replay_buffer:
                    for curr_req in self.replay_buffer:
                        self.handle_ip_req(curr_req['datapath'], 
                                        curr_req['eth'], 
                                        curr_req['ip_pkt'],
                                        curr_req['icmp_pkt'],
                                        curr_req['in_port'], 
                                        curr_req['parser'])
                    self.replay_buffer = []
            
        elif dpid == 3 and ip_pkt:
            protocol = ip_pkt.proto
            # Restricting visibility of internal hosts to external host
            self.logger.info(f'IP request received at device {dpid}')
            src_ip = ipaddress.ip_address(ip_pkt.src)
            dest_ip = ipaddress.ip_address(ip_pkt.dst)
            if protocol == in_proto.IPPROTO_ICMP:
                if dest_ip in self.ext_subnet and src_ip not in self.ext_subnet:
                    self.logger.info("Internal host attempting direct call to external host, blocking the request")
                    match_icmp = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dest_ip, ip_proto=in_proto.IPPROTO_ICMP)
                    actions = []
                    self.add_flow(datapath, 50, match_icmp, actions)
                    return
                elif src_ip in self.ext_subnet and dest_ip not in self.ext_subnet:
                    self.logger.info("External host attempting direct call to internal host, blocking request")
                    match_icmp = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dest_ip, ip_proto=in_proto.IPPROTO_ICMP)
                    actions = []
                    self.add_flow(datapath, 50, match_icmp, actions)
                    return
            elif protocol == in_proto.IPPROTO_TCP or protocol == in_proto.IPPROTO_UDP:
                if (src_ip in self.ext_subnet and dest_ip in self.ser_subnet) or \
                    (src_ip in self.ser_subnet and dest_ip in self.ext_subnet):
                    self.logger.info("Blocking direct TCP/UDP connections between server and external host")
                    match_tcp = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dest_ip, ip_proto=in_proto.IPPROTO_TCP)
                    match_udp = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dest_ip, ip_proto=in_proto.IPPROTO_UDP)
                    actions = []
                    self.add_flow(datapath, 50, match_tcp, actions)
                    self.add_flow(datapath, 50, match_udp, actions)
                    return
                    
            self.handle_ip_req(datapath, eth, ip_pkt, icmp_pkt, in_port, parser)
        else:
            self.logger.info(f'Packet received at device {dpid}')
            self.send_packet_lev2(datapath, dpid, eth, msg, ofproto, parser)
        