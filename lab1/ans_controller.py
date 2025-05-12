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
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, icmp


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Initialize data structures for the controller

        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }

        # For switches
        self.mac_to_port = {}
        # For router
        self.ip_to_mac = {}
        # In case an ARP reqeust needs to be sent by the router before sending the packet
        self.buffered_packets = {}
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath

        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        datapath_id = datapath.id
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        destination = eth.dst
        source = eth.src

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if datapath_id not in self.mac_to_port:
            self.mac_to_port[datapath_id] = {}

        # Switch logic for s1 and s2
        if datapath_id in [1, 2]:
            #self.logger.info("Switch %s handling packet: %s -> %s", datapath_id, source, destination)
            # Learn MAC address to port mapping
            self.mac_to_port[datapath_id][source] = in_port

            if destination in self.mac_to_port[datapath_id]:
                out_port = self.mac_to_port[datapath_id][destination]
            else:
                out_port = ofp.OFPP_FLOOD

            actions = [ofp_parser.OFPActionOutput(out_port)]

            # Install a flow if the destination MAC is known
            if out_port != ofp.OFPP_FLOOD:
                match = ofp_parser.OFPMatch(
                    in_port=in_port, eth_dst=destination, eth_src=source)
                self.add_flow(datapath, 1, match, actions)

            # Send the packet
            out = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)

            # ROUTER LOGIC for s3
        elif datapath_id == 3:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            arp_pkt = pkt.get_protocol(arp.arp)

            # ARP packets
            if arp_pkt:
                
                self.ip_to_mac[arp_pkt.src_ip] = arp_pkt.src_mac  # learn sender MAC dynamically

                # Replay buffered packets
                if arp_pkt.src_ip in self.buffered_packets:
                    self.logger.info("Router is sending buffered packet")
                    for dp, in_port_buf, msg_buf, out_port in self.buffered_packets[arp_pkt.src_ip]:
                        parser = dp.ofproto_parser
                        ofp = dp.ofproto

                        src_mac = self.port_to_own_mac[out_port]
                        dst_mac = arp_pkt.src_mac

                        actions = [
                            parser.OFPActionSetField(eth_src=src_mac),
                            parser.OFPActionSetField(eth_dst=dst_mac),
                            parser.OFPActionOutput(out_port)
                        ]
                        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=arp_pkt.src_ip)
                        self.add_flow(dp, 10, match, actions)

                        out = parser.OFPPacketOut(datapath=dp,
                                                  buffer_id=msg_buf.buffer_id,
                                                  in_port=in_port_buf,
                                                  actions=actions,
                                                  data=msg_buf.data)
                        dp.send_msg(out)
                        
                    del self.buffered_packets[arp_pkt.src_ip]

                if arp_pkt.opcode == arp.ARP_REQUEST:
                    self.logger.info("Router is handling ARP request")
                    target_ip = arp_pkt.dst_ip
                    for port, ip in self.port_to_own_ip.items():
                        if target_ip == ip:
                            src_mac = self.port_to_own_mac[port]
                            arp_reply = packet.Packet()
                            arp_reply.add_protocol(ethernet.ethernet(
                                ethertype=ether_types.ETH_TYPE_ARP,
                                src=src_mac,
                                dst=arp_pkt.src_mac))
                            arp_reply.add_protocol(arp.arp(
                                opcode=arp.ARP_REPLY,
                                src_mac=src_mac,
                                src_ip=target_ip,
                                dst_mac=arp_pkt.src_mac,
                                dst_ip=arp_pkt.src_ip
                            ))
                            arp_reply.serialize()
                            actions = [ofp_parser.OFPActionOutput(in_port)]
                            out = ofp_parser.OFPPacketOut(
                                datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=ofp.OFPP_CONTROLLER, actions=actions,
                                data=arp_reply.data)
                            datapath.send_msg(out)
                            return                

            # IPv4 packets
            elif ipv4_pkt:
                self.logger.info(
                    "Router is handling IPv4 packet: %s -> %s", ipv4_pkt.src, ipv4_pkt.dst)
                dst_ip = ipv4_pkt.dst
                src_ip = ipv4_pkt.src
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                

                # BLOCK traffic from ext to internal hosts or internal hosts to ext
                if (src_ip == "192.168.1.123" and dst_ip.startswith("10.")) or (src_ip.startswith("10.") and dst_ip == "192.168.1.123"):
                    self.logger.info("Dropping packet from ext to internal host / internal host to ext")
    
                    # Match ext -> internal
                    match1 = ofp_parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src="192.168.1.123",
                        ipv4_dst=("10.0.0.0", "255.0.0.0")
                        )

                    # Match internal -> ext
                    match2 = ofp_parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=("10.0.0.0", "255.0.0.0"),
                        ipv4_dst="192.168.1.123"
                        )

                    actions = []  # drop = no actions

                    self.add_flow(datapath, 20, match1, actions)
                    self.add_flow(datapath, 20, match2, actions)

                    return  # drop the triggering packet


                # ICMP Echo Reply to own gateway — and block cross-subnet
                if dst_ip in self.port_to_own_ip.values() and icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    allowed = (
                        dst_ip == "10.0.1.1" and src_ip.startswith("10.0.1.") or
                        dst_ip == "10.0.2.1" and src_ip.startswith("10.0.2.") or
                        dst_ip == "192.168.1.1" and src_ip.startswith("192.168.1.")
                    )
                    if not allowed:
                        self.logger.info("Blocked ICMP to non-local gateway: %s from %s", dst_ip, src_ip)
                        return

                    eth_reply = ethernet.ethernet(dst=eth.src, src=eth.dst, ethertype=eth.ethertype)
                    ip_reply = ipv4.ipv4(dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto)
                    icmp_reply = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=0, csum=0, data=icmp_pkt.data)
                    reply_pkt = packet.Packet()
                    reply_pkt.add_protocol(eth_reply)
                    reply_pkt.add_protocol(ip_reply)
                    reply_pkt.add_protocol(icmp_reply)
                    reply_pkt.serialize()
                    actions = [ofp_parser.OFPActionOutput(in_port)]
                    out = ofp_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=ofp.OFPP_CONTROLLER,
                        actions=actions,
                        data=reply_pkt.data
                    )
                    datapath.send_msg(out)
                    return


                # Decide output port based on dst_ip
                out_port = None
                for port, subnet_ip in self.port_to_own_ip.items():
                    if dst_ip.startswith(subnet_ip.rsplit('.', 1)[0] + '.'):
                        out_port = port
                        break

                if out_port is None:
                    self.logger.info("Unknown destination IP: %s — dropping", dst_ip)
                    return

                
                 # Get learned MAC for dst_ip
                if dst_ip not in self.ip_to_mac:
                    self.logger.info("Sending ARP request for %s", dst_ip)
                    src_mac = self.port_to_own_mac[out_port]
                    src_ip = self.port_to_own_ip[out_port]

                    arp_request = packet.Packet()
                    arp_request.add_protocol(ethernet.ethernet(
                        ethertype=ether_types.ETH_TYPE_ARP,
                        dst='ff:ff:ff:ff:ff:ff',
                        src=src_mac))
                    arp_request.add_protocol(arp.arp(
                        opcode=arp.ARP_REQUEST,
                        src_mac=src_mac,
                        src_ip=src_ip,
                        dst_mac='00:00:00:00:00:00',
                        dst_ip=dst_ip
                    ))
                    arp_request.serialize()
                    actions = [ofp_parser.OFPActionOutput(out_port)]
                    out = ofp_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=ofp.OFPP_CONTROLLER, actions=actions,
                        data=arp_request.data)
                    datapath.send_msg(out)

                    if dst_ip not in self.buffered_packets:
                        self.buffered_packets[dst_ip] = []
                    self.buffered_packets[dst_ip].append((datapath, in_port, msg, out_port))
                    return

                dst_mac = self.ip_to_mac[dst_ip]
                src_mac = self.port_to_own_mac[out_port]

                actions = [
                    ofp_parser.OFPActionSetField(eth_src=src_mac),
                    ofp_parser.OFPActionSetField(eth_dst=dst_mac),
                    ofp_parser.OFPActionOutput(out_port)
                ]
                match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
                self.add_flow(datapath, 10, match, actions)

                out = ofp_parser.OFPPacketOut(datapath=datapath,
                                              buffer_id=msg.buffer_id,
                                              in_port=in_port,
                                              actions=actions,
                                              data=msg.data)
                datapath.send_msg(out)
