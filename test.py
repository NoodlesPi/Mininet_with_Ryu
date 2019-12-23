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
import time
from topo_manager_example import TopoManager

import numpy as np

class ShortestPathSwitching(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    flag = True


    def update(self):
        self.switch_to = [[1000000 for i in range(self.switchNum+1)] for i in range(self.switchNum+1)]

        for x in range(1, self.switchNum+1):
            self.switch_to[x][x] = 0
        for key in self.mac_mac:
            macA = key
            macB = self.mac_mac[key]
            a = self.sMac_num[macA]
            b = self.sMac_num[macB]
            self.switch_to[a][b] = 1

        for k in range(1, self.switchNum+1):
            for i in range(1, self.switchNum+1):
                for j in range(1, self.switchNum+1):
                    if self.switch_to[i][k] + self.switch_to[k][j] < self.switch_to[i][j]:
                        self.switch_to[i][j] = self.switch_to[i][k] + self.switch_to[k][j]
        self.set_flowtable()
        self.print_path()


    def __init__(self, *args, **kwargs):
        super(ShortestPathSwitching, self).__init__(*args, **kwargs)

        self.tm = TopoManager()

    ################################################################################################################

        self.switchNum = 0

        self.switch_to = []

        self.numInfo = []

        self.switch_num_real = {}  #转化交换机序号为真实序号，编程用
        self.switch_real_num = {}  # 转化交换机序号为真实序号，编程用
        self.port = []

        self.hIp_hMac = {}
        self.hMac_sMac = {}
        self.sMac_sPort = {}

        self.mac_mac = {}

        self.sMac_num = {}
        self.hIp_realNum = {}

        self.sId_sWitch = {}  # 交换机id和交换机datapath对应

        self.switch_to.append([])

        self.numInfo.append([])

        self.leaveSwitchList = []
        self.DelPortList = []
    ################################################################################################################


    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        """
        Event handler indicating a switch has come onlin            self.logger.info(paths)e.
        """
        switch = ev.switch
        dp = switch.dp
        self.sId_sWitch[dp.id] = dp

        self.logger.warn("Added Switch switch%d with ports:", switch.dp.id)

        self.switchNum += 1
        self.switch_to.append([])
        self.numInfo.append([])

        for port in switch.ports:
            self.logger.warn("\t%d:  %s", port.port_no, port.hw_addr)

            self.sMac_sPort[port.hw_addr] = port.port_no
            self.numInfo[self.switchNum].append(port.hw_addr)
            self.switch_to[self.switchNum].append(0)

            self.sMac_num[port.hw_addr] = self.switchNum

        self.switch_real_num[switch.dp.id] = self.switchNum
        self.switch_num_real[self.switchNum] = switch.dp.id
        # TODO:  Update network topology and flow rules
        self.tm.add_switch(switch)
        self.update()

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        """
        Event handler indicating a switch has been removed
        """
        switch = ev.switch

        self.logger.warn("Removed Switch switch%d with ports:", switch.dp.id)
        for port in switch.ports:
            self.logger.warn("\t%d:  %s", port.port_no, port.hw_addr)

        fakeNum = self.switch_real_num[switch.dp.id]
        self.leaveSwitchList.append(fakeNum)

        for mac in self.numInfo[fakeNum]:  ####################################################
            if mac in self.mac_mac:
                del self.mac_mac[self.mac_mac[mac]]
                del self.mac_mac[mac]

        # TODO:  Update network topology and flow rules
        self.update()

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """


        host = ev.host
        self.logger.warn("Host Added:  %s (IPs:  %s) on switch%s/%s (%s)",
                          host.mac, host.ipv4, host.port.dpid, host.port.port_no, host.port.hw_addr)

        # TODO:  Update network topology and flow rules

        self.hIp_hMac[host.ipv4[0]] = host.mac
        self.hMac_sMac[host.mac] = host.port.hw_addr

        # real = self.switch_real_num[host.port.dpid] ########################################
        self.hIp_realNum[host.ipv4[0]]= host.port.dpid #####################


        self.tm.add_host(host)
        self.update()

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
        #########################################################################################################

        self.mac_mac[src_port.hw_addr] = dst_port.hw_addr
        self.mac_mac[dst_port.hw_addr] = src_port.hw_addr


        #########################################################################################################
        # TODO:  Update network topology and flow rules
        self.update()

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
        #########################################################################################################

        if src_port.hw_addr in self.mac_mac:

            del self.mac_mac[src_port.hw_addr]
        if dst_port.hw_addr in self.mac_mac:

            del self.mac_mac[dst_port.hw_addr]

        #########################################################################################################
        # TODO:  Update network topology and flow rules
        self.update()

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
        #########################################################################################################
        a = self.sMac_num[port.hw_addr]

        if port.hw_addr in self.mac_mac:
            b = self.sMac_num[self.mac_mac[port.hw_addr]]

            if port.hw_addr in self.DelPortList:
                self.DelPortList.remove(port.hw_addr)
                self.switch_to[a][b] = 1
                self.switch_to[b][a] = 1
            else:
                self.DelPortList.append(port.hw_addr)
                if port.hw_addr in self.mac_mac:
                    # del self.mac_mac[self.mac_mac[port.hw_addr]]
                    # del self.mac_mac[port.hw_addr]
                    self.switch_to[a][b] = 1000000
                    self.switch_to[b][a] = 1000000
        #########################################################################################################
        # TODO:  Update network topology and flow rules
        self.update()

    def delete_forwarding_rule(self, datapath, dl_dst):
        ofctl = OfCtl.factory(datapath, self.logger)

        match = datapath.ofproto_parser.OFPMatch(dl_dst=dl_dst)
        ofctl.delete_flow(cookie=0, priority=0, match=match)

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

            if arp_msg.opcode == arp.ARP_REQUEST:
                self.logger.warning("Received ARP REQUEST on switch%d/%d:  Who has %s?  Tell %s",
                                    dp.id, in_port, arp_msg.dst_ip, arp_msg.src_mac)
                paths = self.get_path(arp_msg.src_ip, arp_msg.dst_ip)
                self.logger.info('Path:%s',paths)
                # TODO:  Generate a *REPLY* for this request based on your switch state
                ofctl.send_arp(
                    vlan_id=VLANID_NONE,
                    src_port=ofctl.dp.ofproto.OFPP_CONTROLLER,
                    dst_mac=arp_msg.src_mac,
                    sender_ip=arp_msg.dst_ip,
                    sender_mac=self.hIp_hMac[arp_msg.dst_ip],
                    target_ip=arp_msg.src_ip,
                    target_mac=arp_msg.src_mac,
                    output_port=self.sMac_sPort[self.hMac_sMac[arp_msg.src_mac]],
                    arp_opcode=2
                )

                # Here is an example way to send an ARP packet using the ofctl utilities
                #ofctl.send_arp(vlan_id=VLANID_NONE,
                #               src_port=ofctl.dp.ofproto.OFPP_CONTROLLER,
                #               . . .)




    def print_path(self):
        host_table = self.get_hostTable()
        ad_table = self.get_linkTable()
        for index in range(len(ad_table)):
            if index != 0:
                string = 'Switch' + str(index) + ':'
                for tuple in ad_table[index]:
                    string += 'port' + str(tuple[1]) + '->Switch' + str(tuple[0]) + ' | '
                for host in host_table:
                    if host[1] == index:
                        string += 'port' + str(host[2]) + '->Host-' + str(host[0]) + ' | '
                self.logger.info(string)

    def get_path(self,src_ip,dst_ip):
        ipA = src_ip  #输入其实主机IP
        ipB = dst_ip  #输入目的地主机IP

        startMac = self.hMac_sMac[self.hIp_hMac[ipA]]
        endMac = self.hMac_sMac[self.hIp_hMac[ipB]]

        startNum = self.sMac_num[startMac]
        endNum = self.sMac_num[endMac]

        nowNum = startNum

        ans_list=[]

        while nowNum != endNum:
            minDistance = self.switch_to[nowNum][endNum]
            nextNum = nowNum

            outputNum = self.switch_num_real[nowNum]
            outputPort = -1

            for mac in self.numInfo[nowNum]:
                if mac in self.mac_mac:
                    tempNum = self.sMac_num[self.mac_mac[mac]]
                    if self.switch_to[tempNum][endNum] <minDistance:
                        nextNum = tempNum
                        minDistance = self.switch_to[tempNum][endNum]
                        outputPort = self.sMac_sPort[mac]

            ans_list.append((outputNum, outputPort))
            testNum = nowNum
            nowNum = nextNum
            if testNum == nowNum:
                return []


        lastNum = self.switch_num_real[endNum]
        lastPort = self.sMac_sPort[endMac]
        ans_list.append((lastNum,lastPort))
        return ans_list

    def set_flowtable(self):
        ipList = [] #所有ip
        for key in self.hIp_hMac:
            ipList.append(key)
        #任意两个ip之间都添加对应的流表
        for ip1 in ipList:
            for ip2 in ipList:
                if ip1 != ip2:
                    tuple_list = self.get_path(ip1,ip2)
                    for tuple in tuple_list:
                        #先删除旧流表再添加流表
                        self.delete_forwarding_rule(self.sId_sWitch[tuple[0]], self.hIp_hMac[ip2])
                        self.add_forwarding_rule(self.sId_sWitch[tuple[0]], self.hIp_hMac[ip2], tuple[1])

    def get_linkTable(self):

        table = []
        for i in range(self.switchNum+1):
            table.append([])

        for link in self.numInfo:
            start = 0
            for mac in link:
                if mac in self.mac_mac:
                    start = self.switch_num_real[self.sMac_num[mac]]
                    aim = self.switch_num_real[self.sMac_num[self.mac_mac[mac]]]
                    port = self.sMac_sPort[mac]
                    table[start].append((aim,port))
        return table

    def get_hostTable(self):
        table = []



        for i in self.hIp_realNum:
            num = self.hIp_realNum[i]
            mac = self.hIp_hMac[i]
            aimMac = self.hMac_sMac[mac]
            aimFake = self.sMac_num[aimMac]
            aim = self.switch_num_real[aimFake]

            port = self.sMac_sPort[aimMac]
            table.append((i,aim,port))
        return table
