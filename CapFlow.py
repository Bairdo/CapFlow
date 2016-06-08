
# Python
import collections

# Ryu - OpenFlow
from ryu.base import app_manager
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.lib.packet import ethernet, ipv4, tcp, udp, dhcp, arp
from ryu.lib.packet import packet
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3
import ryu.utils as utils


# Ryu - REST API
from ryu.app.wsgi import WSGIApplication
from ryu.controller import dpset

# Us
import config
import util
from rest import UserController


class Proto(object):
    ETHER_IP = 0x800
    ETHER_ARP = 0x806
    IP_UDP = 17
    IP_TCP = 6
    TCP_HTTP = 80
    UDP_DNS = 53


class CapFlow(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(CapFlow, self).__init__(*args, **kwargs)
        self.mac_to_port = collections.defaultdict(dict)
        self.authenticate = collections.defaultdict(dict)
        wsgi = kwargs['wsgi']

        wsgi.registory['UserController'] = self.authenticate
        UserController.register(wsgi)
        
        
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        self.logger.info('OFPFlowRemoved received: '
                          'cookie=%d priority=%d reason=%s table_id=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'idle_timeout=%d hard_timeout=%d '
                          'packet_count=%d byte_count=%d match.fields=%s',
                          msg.cookie, msg.priority, reason, msg.table_id,
                          msg.duration_sec, msg.duration_nsec,
                          msg.idle_timeout, msg.hard_timeout,
                          msg.packet_count, msg.byte_count, msg.match)
        
    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg

        self.logger.warning('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s',
                          msg.type, msg.code, utils.hex_array(msg.data))
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print "Clear rule table"
        util.delete_flow(datapath, parser.OFPMatch())

        # Send everything to ctrl
        print "Install sending to controller rule"
        util.add_flow(datapath,
            parser.OFPMatch(),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
            priority=2,
        )

        # flows to block traffic from other side of network. (doesnt affect us)
        util.add_flow(datapath,
                    parser.OFPMatch(in_port=1, eth_src="A4:77:33:0E:B6:03"),
                    [], 10000)
        util.add_flow(datapath,
                    parser.OFPMatch(in_port=1, eth_src="A4:77:33:0E:B6:03"),
                    [], 10000)
        
        util.add_flow(datapath,
                    parser.OFPMatch(in_port=1, eth_src="30:75:12:AF:58:C1"),
                    [], 10000)
                    
        util.add_flow(datapath,
                    parser.OFPMatch(in_port=1, eth_src="40:61:86:C0:AE:95"),
                    [], 10000)     
                    
        util.add_flow(datapath,
                    parser.OFPMatch(in_port=1, eth_src="24:DF:6A:84:63:D4"),
                    [], 10000)  
        
     
        
        
        # So we don't need to learn auth server location
        # TODO: this assumes we are controlling only a single switch!
        port = config.AUTH_SERVER_PORT
        self.mac_to_port[datapath.id][config.AUTH_SERVER_MAC] = port


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        nw_dst = eth.dst
        nw_src = eth.src

        dpid = datapath.id

        self.logger.info("packet type %s at switch %s from %s to %s (port %s)",
                         eth.ethertype , dpid, nw_src, nw_dst, in_port)

        if nw_src not in self.mac_to_port[dpid]:
            
            print "     New client: dpid", dpid, "mac", nw_src, "port", in_port
            self.mac_to_port[dpid][nw_src] = in_port
            # Be sure to not forward ARP traffic so we can learn
            # sources
            util.add_flow(datapath,
                parser.OFPMatch(
                    eth_dst=nw_src,
                    eth_type=Proto.ETHER_ARP,
                ),
                [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER), ],
                priority=1000,
                msg=msg, in_port=in_port,
            )

        # pass ARP through, defaults to flooding if destination unknown
        if eth.ethertype == Proto.ETHER_ARP:
            arp_pkt = pkt.get_protocols(arp.arp)[0]
            self.logger.info("      ARP packet: dpid %s, mac_src %s, arp_ip_src %s, arp_ip_dst %s, in_port %s", dpid, nw_src, arp_pkt.src_ip, arp_pkt.dst_ip, in_port)
            ##self.logger.info("New client: dpid: " + str(dpid) + " mac: " + str(nw_src) + " port: " + str(in_port) + "src ip" + str(arp_pkt.src_ip) + " dst ip:" + str(arp_pkt.dst_ip))
            ##self.logger.info("ARP, buffer id: " + str(msg.buffer_id))
            port = self.mac_to_port[dpid].get(nw_dst, ofproto.OFPP_FLOOD)
            ##self.logger.info("src: " + nw_src + " dst: " + nw_dst + "")
            out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=[parser.OFPActionOutput(port)],
                    data=msg.data)
            if port == ofproto.OFPP_FLOOD:
                self.logger.info("      Flooding")
            else:
                self.logger.info("      ARP out Port" + str(port))
            datapath.send_msg(out)
            return

        if eth.ethertype == Proto.ETHER_IP:
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            if ip.proto == Proto.IP_UDP:
                dh = None
                try:
                    dh = pkt.get_protocols(dhcp.dhcp)[0]


                    if dh is not None:
                        self.logger.info("      this is a dhcp packet")
                        if dh.op == 1:
                            # request
                            self.logger.info("          sending dhcp request to gateway")
                            # allow the dhcp request/discover
                            '''util.add_flow(datapath,
                                    parser.OFPMatch(
                                        eth_dst="FF:FF:FF:FF:FF:FF",
                                        eth_type=Proto.ETHER_IP,
                                        ipv4_src="0.0.0.0",
                                        ipv4_dst="255.255.255.255",
                                        ip_proto=Proto.IP_UDP,
                                        udp_dst=67,
                                        udp_src=68
                                    ),
                                    [parser.OFPActionOutput(config.GATEWAY_PORT)],
                                    priority=30
                                )'''
                            out = parser.OFPPacketOut(
                                datapath=datapath,
                                buffer_id=msg.buffer_id,
                                in_port=in_port,
                                actions=[parser.OFPActionOutput(config.GATEWAY_PORT)],
                                data=msg.data)#,
                            
                            
                            datapath.send_msg(out)
                            return
                        elif dh.op == 2:
                            self.logger.info("          dhcp reply, flooding if unknown dest")
                            # todo change this so we dont flood.
                            p = self.mac_to_port[dpid][nw_dst]
                            
                            out = parser.OFPPacketOut(
                            datapath=datapath,
                            buffer_id=msg.buffer_id,
                            in_port=in_port,
                            actions=[parser.OFPActionOutput(p)],
                            data=msg.data)
                        
                            datapath.send_msg(out)
                            return
                        
                    else:
                        self.logger.info("      this wasnt a dhcp packet")
                except IndexError:
                    self.logger.info("      index error with trying to get dhcp packet")
            
        # Non-ARP traffic to unknown L2 destination is dropped
        if nw_dst not in self.mac_to_port[dpid]:
            #self.logger.info("      Unknown destination!")
            return

        # We know L2 destination
        out_port = self.mac_to_port[dpid][nw_dst]

        # Helper functions (note: access variables from outer scope)
        def install_l2_src_dst(nw_src, nw_dst, out_port):
            util.add_flow(datapath,
                parser.OFPMatch(
                    eth_src=nw_src,
                    eth_dst=nw_dst,
                ),
                [parser.OFPActionOutput(out_port), ],
                priority=50000,
                msg=msg, in_port=in_port,
            )

        def install_dns_fwd(nw_src, nw_dst, out_port, src_port):
            self.logger.info("              adding dns flows")
            # this should just be for before we authenticate. (once authed all traffic allowed at L2). so have relatively short timeout on rule
            # dns response packet
            util.add_flow(datapath,
                parser.OFPMatch(
                    eth_src=nw_dst,
                    eth_dst=nw_src,
                    eth_type=Proto.ETHER_IP,
                    ip_proto=Proto.IP_UDP,
                    udp_dst=src_port,
                    udp_src=Proto.UDP_DNS
                ),
                [parser.OFPActionOutput(in_port)],
                priority=2001,
                msg=msg, in_port=out_port, idle_timeout=10
            )
            # dns query packets
            util.add_flow(datapath,
                parser.OFPMatch(
                    eth_src=nw_src,
                    eth_dst=nw_dst,
                    eth_type=Proto.ETHER_IP,
                    ip_proto=Proto.IP_UDP,
                    udp_dst=Proto.UDP_DNS,
                    udp_src=src_port
                    #todo add src/dst ports
                ),
                [parser.OFPActionOutput(out_port)],
                priority=2000,
                msg=msg, in_port=in_port, idle_timeout=10
            )
            out = parser.OFPPacketOut(
                                datapath=datapath,
                                buffer_id=msg.buffer_id,
                                in_port=in_port,
                                actions=[parser.OFPActionOutput(config.GATEWAY_PORT)],
                                data=msg.data)#,
                            
                            
            datapath.send_msg(out)
            

        def install_http_nat(nw_src, nw_dst, ip_src, ip_dst, tcp_src, tcp_dst):
            # TODO: we do not change port right now so it might collide with
            # other connections from the host. This is unlikely though

            # Reverse rule goes first
            match = parser.OFPMatch(
                    in_port=config.AUTH_SERVER_PORT,
                    eth_src=config.AUTH_SERVER_MAC,
                    eth_dst=nw_src,
                    eth_type=Proto.ETHER_IP,
                    ip_proto=Proto.IP_TCP,
                    ipv4_src=config.AUTH_SERVER_IP,
                    ipv4_dst=ip_src,
                    tcp_dst=tcp_src,
                    tcp_src=tcp_dst,
                )
                
            util.add_flow(datapath,
                match,
                [parser.OFPActionSetField(ipv4_src=ip_dst),
                 parser.OFPActionSetField(eth_src=nw_dst),
                 parser.OFPActionOutput(in_port)
                ],
                priority=1000, idle_timeout=5
            )
            
            self.logger.info("reverse match: %s", match)
            
            match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=nw_src,
                    eth_dst=nw_dst,
                    eth_type=Proto.ETHER_IP,
                    ip_proto=Proto.IP_TCP,
                    ipv4_src=ip_src,
                    ipv4_dst=ip_dst,
                    tcp_dst=tcp_dst,
                    tcp_src=tcp_src,
                )
            self.logger.info("forward match %s", match)
            # Forward rule
            util.add_flow(datapath,
                match,
                [parser.OFPActionSetField(ipv4_dst=config.AUTH_SERVER_IP),
                 parser.OFPActionSetField(eth_dst=config.AUTH_SERVER_MAC),
                 parser.OFPActionOutput(config.AUTH_SERVER_PORT)
                ],
                priority=1001,
                msg=msg, in_port=in_port, idle_timeout=5
            )
            out = parser.OFPPacketOut(
                                datapath=datapath,
                                buffer_id=msg.buffer_id,
                                in_port=in_port,
                                actions=[parser.OFPActionSetField(ipv4_dst=config.AUTH_SERVER_IP),
                                         parser.OFPActionSetField(eth_dst=config.AUTH_SERVER_MAC),
                                         parser.OFPActionOutput(config.AUTH_SERVER_PORT)]
                                         )#,
                            
                            
            datapath.send_msg(out)
        def drop_unknown_ip(nw_src, nw_dst, ip_proto):
            util.add_flow(datapath,
                parser.OFPMatch(
                    eth_src=nw_src,
                    eth_dst=nw_dst,
                    eth_type=Proto.ETHER_IP,
                    ip_proto=ip_proto,
                ),
                [],
                priority=10,
                msg=msg, in_port=in_port,
            )

        if eth.ethertype != Proto.ETHER_IP:
            self.logger.info("      not handling non-ip traffic")
            return

        ip = pkt.get_protocols(ipv4.ipv4)[0]

        # Is this communication allowed?
        # Allow if both src/dst are authenticated and
        l2_traffic_is_allowed = False
        
        for entry in config.WHITELIST:
            if nw_src == entry[0] and nw_dst == entry[1]:
                l2_traffic_is_allowed = True
        if self.authenticate[ip.src] and self.authenticate[ip.dst]:
            l2_traffic_is_allowed = True
        if self.authenticate[ip.src] and nw_dst == config.GATEWAY_MAC:
            l2_traffic_is_allowed = True
        if nw_src == config.GATEWAY_MAC and self.authenticate[ip.dst]:
            l2_traffic_is_allowed = True

        if l2_traffic_is_allowed:
            self.logger.info("      authenticated")
            self.logger.info("      Installing %s to %s bypass", nw_src, nw_dst)
            install_l2_src_dst(nw_src, nw_dst, out_port)
            return

        # Client authenticated but destination not, just block it
        if self.authenticate[ip.src]:
            self.logger.info("      Auth client sending to non-auth destination blocked! " + str(ip.dst))
            self.logger.info("      packet type %s, eth.dst %s, eth.src %s", ip.proto, eth.dst, eth.src)
                                
            self.logger.info("      ip.dst %s ip.src %s", ip.dst, ip.src)
            
            self.logger.info("      gateway mac: %s", config.GATEWAY_MAC)
            return
        # Client is not authenticated
        if ip.proto == 1:
            self.logger.info("      ICMP, ignore")
            return
        if ip.proto == Proto.IP_UDP:
            _udp = pkt.get_protocols(udp.udp)[0]
            if _udp.dst_port == Proto.UDP_DNS:
                self.logger.info("      Install DNS bypass")
                install_dns_fwd(nw_src, nw_dst, out_port, _udp.src_port)
            else:
                self.logger.info("  Unknown UDP proto, ignore, port: " + str(_udp.dst_port))
                return
        elif ip.proto == Proto.IP_TCP:
            _tcp = pkt.get_protocols(tcp.tcp)[0]
            if _tcp.dst_port == Proto.TCP_HTTP:
                self.logger.info("      Is HTTP traffic, installing NAT entry. in interface: %d", in_port)
                self.logger.info("      ip.src: %s ip.dst: %s", ip.src, ip.dst)
                install_http_nat(nw_src, nw_dst, ip.src, ip.dst,
                                 _tcp.src_port, _tcp.dst_port)
        else:
            self.logger.info("      Unknown IP proto: " + ip.proto +", dropping")
            drop_unknown_ip(nw_src, nw_dst, ip.proto)
