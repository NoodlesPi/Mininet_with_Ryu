#!/usr/bin/env python3

"""Shortest Path Switching template
CSCI1680

This example creates a simple controller application that watches for
topology events.  You can use this framework to collect information
about the network topology and install rules to implement shortest
path switching.

"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0

from ryu.topology import event, switches
import ryu.topology.api as topo

from ryu.lib.packet import packet, ether_types
from ryu.lib.packet import ethernet, arp, icmp

from ofctl_utils import OfCtl, VLANID_NONE

from topo_manager_example import TopoManager


class ShortestPathSwitching(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    hMac_sPort = {}#host mac地址和交换机端口对应

    hIp_hMac = {}#host ip和host mac地址对应

    sMac_sMac = {}#交换机mac地址和交换机mac地址之间的对应

    sId_sWitch = {}#交换机id和交换机datapath对应

    sWitch_dicts = {}#以ID检索switch字典


    def __init__(self, *args, **kwargs):
        super(ShortestPathSwitching, self).__init__(*args, **kwargs)

        self.tm = TopoManager()

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        """
        Event handler indicating a switch has come online.
        """
        switch = ev.switch
        dp = switch.dp
        self.sId_sWitch[dp.id] = dp

        self.logger.warn("Added Switch switch%d with ports:", switch.dp.id)
        sMac_sPort = {}  # 交换机port和mac地址的对应
        for port in switch.ports:
            sMac_sPort[port.hw_addr] = port.port_no
            self.logger.warn("\t%d:  %s", port.port_no, port.hw_addr)
        self.sWitch_dicts[dp.id] = sMac_sPort

        # TODO:  Update network topology and flow rules
        self.tm.add_switch(switch)

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        """
        Event handler indicating a switch has been removed
        """
        switch = ev.switch

        self.logger.warn("Removed Switch switch%d with ports:", switch.dp.id)
        for port in switch.ports:
            self.logger.warn("\t%d:  %s", port.port_no, port.hw_addr)

        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """
        host = ev.host
        self.logger.warn("Host Added:  %s (IPs:  %s) on switch%s/%s (%s)",
                          host.mac, host.ipv4,
                         host.port.dpid, host.port.port_no, host.port.hw_addr)
        self.hIp_hMac[host.ipv4[0]] = host.mac
        self.hMac_sPort[host.mac] = self.sWitch_dicts[host.port.dpid][host.port.hw_addr]
        # TODO:  Update network topology and flow rules
        self.tm.add_host(host)

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """
        Event handler indicating a link between two switches has been added
        """
        link = ev.link
        src_port = ev.link.src
        dst_port = ev.link.dst
        self.logger.warn("Added Link:  switch%s/%s (%s) -> switch%s/%s (%s)",
                         src_port.dpid, src_port.port_no, src_port.hw_addr,
                         dst_port.dpid, dst_port.port_no, dst_port.hw_addr)

        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Event handler indicating when a link between two switches has been deleted
        """
        link = ev.link
        src_port = link.src
        dst_port = link.dst

        self.logger.warn("Deleted Link:  switch%s/%s (%s) -> switch%s/%s (%s)",
                          src_port.dpid, src_port.port_no, src_port.hw_addr,
                          dst_port.dpid, dst_port.port_no, dst_port.hw_addr)

        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        port = ev.port
        self.logger.warn("Port Changed:  switch%s/%s (%s):  %s",
                         port.dpid, port.port_no, port.hw_addr,
                         "UP" if port.is_live() else "DOWN")

        # TODO:  Update network topology and flow rules

    def add_forwarding_rule(self, datapath, dl_dst, port):
        ofctl = OfCtl.factory(datapath, self.logger)

        actions = [datapath.ofproto_parser.OFPActionOutput(port)]
        ofctl.set_flow(cookie=0, priority=0, dl_type=ether_types.ETH_TYPE_IP, dl_vlan=VLANID_NONE,
                       dl_dst=dl_dst,
                       actions=actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
       EventHandler for PacketIn messages
        """
        msg = ev.msg
        # In OpenFlow, switches are called "datapaths".  Each switch gets its own datapath ID.
        # In the controller, we pass around datapath objects with metadata about each switch.
        dp = msg.datapath

        # Use this object to create packets for the given datapath
        ofctl = OfCtl.factory(dp, self.logger)

        in_port = msg.in_port
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_msg = pkt.get_protocols(arp.arp)[0]
            self.logger.info(self.sId_sWitch)
            if arp_msg.opcode == arp.ARP_REQUEST:
                self.logger.warning("Received ARP REQUEST on switch%d/%d:  Who has %s?  Tell %s",
                                    dp.id, in_port, arp_msg.dst_ip, arp_msg.src_mac)


                mac = self.hIp_hMac[arp_msg.dst_ip]
                port = self.hMac_sPort[mac]

                #添加flow table

                path = []
                #for tuple in path:

                # self.add_forwarding_rule(self.sId_sWitch[2],'00:00:00:00:00:01', 2)
                # self.add_forwarding_rule(self.sId_sWitch[2], '00:00:00:00:00:02', 1)
                # self.add_forwarding_rule(self.sId_sWitch[1], '00:00:00:00:00:01', 1)
                # self.add_forwarding_rule(self.sId_sWitch[1], '00:00:00:00:00:02', 2)
                #发送arp响应报文
                self.add_forwarding_rule(dp, mac, port)
                ofctl.send_arp(
                    vlan_id=VLANID_NONE,
                    src_port=ofctl.dp.ofproto.OFPP_CONTROLLER,
                    dst_mac=arp_msg.src_mac,
                    sender_ip=arp_msg.dst_ip,
                    sender_mac=self.hIp_hMac[arp_msg.dst_ip],
                    target_ip=arp_msg.src_ip,
                    target_mac=arp_msg.src_mac,
                    output_port=self.hMac_sPort[arp_msg.src_mac],
                    arp_opcode=2
                )



                # if arp_msg.dst_ip == '10.0.0.2':
                #     self.add_forwarding_rule(dp,mac,port)
                #     ofctl.send_arp(vlan_id=VLANID_NONE,
                #                    src_port=ofctl.dp.ofproto.OFPP_CONTROLLER,
                #                    dst_mac="00:00:00:00:00:01",
                #                    sender_ip="10.0.0.2",
                #                    sender_mac="00:00:00:00:00:02",
                #                    target_ip="10.0.0.1",
                #                    target_mac="00:00:00:00:00:01",
                #                    output_port=1,
                #                    arp_opcode=2
                #                    )
                # elif arp_msg.dst_ip == '10.0.0.1':
                #     self.add_forwarding_rule(dp, mac, port)
                #     ofctl.send_arp(vlan_id=VLANID_NONE,
                #                    src_port=ofctl.dp.ofproto.OFPP_CONTROLLER,
                #                    dst_mac="00:00:00:00:00:02",
                #                    sender_ip="10.0.0.1",
                #                    sender_mac="00:00:00:00:00:01",
                #                    target_ip="10.0.0.2",
                #                    target_mac="00:00:00:00:00:02",
                #                    output_port=2,
                #                    arp_opcode=2
                #                    )


                # TODO:  Generate a *REPLY* for this request based on your switch state



