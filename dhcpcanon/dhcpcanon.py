# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2

# Copyright 2016 juga <juga@riseup.net>

# This file is part of dhcpcanon.
#
# dhcpcanon is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# dhcpcanon is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with dhcpcanon.  If not, see <http://www.gnu.org/licenses/>.

"""DCHP client implementation of the anonymity profile (RFC7844)."""

import logging
from netaddr import IPNetwork, IPAddress, AddrFormatError
from scapy.automaton import Automaton,  ATMT
from scapy.arch import get_if_raw_hwaddr
from scapy.layers.dhcp import DHCP, BOOTP, dhcpmagic
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from scapy.utils import str2mac, mac2str
from scapy.config import conf

from dhcpcanon_utils import BROADCAST_MAC, META_ADDR, BROADCAST_ADDR,\
    SERVER_PORT, CLIENT_PORT, PARAM_REQ_LIST,\
    TIMEOUT_DISCOVER, MAX_DISCOVER_RETRIES, MAX_OFFERS_COLLECTED,\
    is_Offer, is_NAK, is_ACK, parse_response, gen_xid,\
    now, gen_renewing_time, gen_rebinding_time, gen_delay_selecting

logger = logging.getLogger(__name__)
# TODO: move constants to configuration file
LEASE_TIME = RENEWING_TIME = REBINDING_TIME = DELAY_SELECTING = None
DEBUG = True


class DHCPCAnon(Automaton):

    def initialize(self, iface=None, client_mac=None,
                   client_ip=None, server_ip=None, server_mac=None,
                   **kargs):
        logger.debug('Initializing client parameters.')
        # fields to send by the client:
        # link layer
        self.server_mac = server_mac
        # ip layer
        self.server_ip = server_ip
        # bootp layer
        # ciaddr and ip layer
        # 3.2.  MUST NOT include in the message a Client IP address that
        # has been obtained with a different link-layer address.
        # NOTE: for the sake of simplicity and anonymity, the previous client
        # ip is never sent in deiscover.
        self.client_ip = client_ip or META_ADDR
        # clients MUST use client identifiers based solely on the link layer
        # address that will be used in the underlying connection.
        # FIXME: RFC 7844, how to convert mac to integer?!!!
        # when converting every digit to int sequencialy, the result is bigger
        # than the maximum xid (4294967295), as in
        # int(''.join(self.client_mac.split(':')), 16)
        # is the maximum xid an scapy restriction?.
        # Note: field not being used:
        # self.client_xid = gen_xid()
        # not included: giaddr, sname, file
        # SHOULD NOT send the Host Name option.
        # SHOULD NOT include the Client FQDN option in their DHCP requests.
        # SHOULD NOT use the Vendor-Specific Information option (code 43).

        # fields received by server:
        # bootp layer
        # dhcp layer
        # siaddr
        self.server_id = ''
        # yiaddr
        self.client_ip_offered = ''
        # dhcp option
        self.subnet_mask = ''
        self.router = ''
        self.name_server = ''
        self.domain = ''
        self.lease_time = 0
        self.options = []
        self.subnet_mask_cidr = ''

        # dhcp logic
        # renewal_time
        self.renewing_time = None
        # rebinding_time
        self.rebinding_time = None
        self.time_sent_request = None
        self.cur_discover_retry = 0
        self.offers = []

    def parse_args(self, iface=None,  server_port=None, client_port=None,
                   client_ip=None, server_ip=None, server_mac=None,
                   client_mac=None, **kargs):
        # NOTE: an external program should randomize MAC prior running this.
        Automaton.parse_args(self, **kargs)
        logger.debug('Automaton parsing args.')
        # in case iface change when going back to init?:
        self.iface = iface or conf.iface
        # link layer:
        # in case mac change when going back to init?:
        # chaddr
        if client_mac is None:
            _, client_mac = get_if_raw_hwaddr(self.iface)
            self.client_mac = str2mac(client_mac)
        else:
            self.client_mac = client_mac
        # upd layer
        self.server_port = server_port or SERVER_PORT
        self.client_port = client_port or CLIENT_PORT
        # dhcp logic
        self.max_discover_retries = MAX_DISCOVER_RETRIES
        self.max_num_offers = MAX_OFFERS_COLLECTED
        self.previous_state = None
        self.current_state = 'INIT'

        self.initialize(iface=iface, client_mac=client_mac,
                        client_ip=client_ip, server_ip=server_ip,
                        server_mac=server_mac)

    def master_filter(self, pkt):
        # the server may probe the offered address with an ICMP Echo Request.
        return (BOOTP in pkt and pkt[BOOTP].options == dhcpmagic and
                pkt[BOOTP].chaddr[:6] == mac2str(self.client_mac) and
                # NOTE: xid not being used.
                # Any DHCPACK messages that arrive with an 'xid' that does
                # not match
                # the 'xid' of the client's DHCPREQUEST message are silently
                #  discarded.
                # pkt[BOOTP].xid == self.client_xid and
                pkt[UDP].sport == self.server_port and
                # FIXME: need to check client port?
                pkt[UDP].dport == self.client_port
                # FIXME: only for replies after bound,
                # this can be done with scapy conf.checkIPaddr:
                # and pkt[IP].dst == self.client_ip
                # and pkt[IP].src == self.server_ip
                )

    def gen_ether_ip_discover(self):
        ether_ip = (
            Ether(src=self.client_mac, dst=BROADCAST_MAC) /
            IP(src=META_ADDR, dst=BROADCAST_ADDR)
        )
        return ether_ip

    def gen_ether_ip_request(self, server_mac=BROADCAST_MAC,
                             server_ip=BROADCAST_ADDR, client_ip=META_ADDR):
        ether_ip = (
            Ether(src=self.client_mac, dst=server_mac) /
            IP(src=client_ip, dst=server_ip)
        )
        return ether_ip

    def gen_udp_bootp(self):
        udp_bootp = (
            UDP(sport=self.client_port, dport=self.server_port) /
            # MAY
            # BOOTP(chaddr=[self.client_mac], xid=self.client_xid) /
            # 3.4. The presence of  "Client hardware address" (chaddr)
            # is necessary for the proper operation of the DHCP service.
            BOOTP(chaddr=[mac2str(self.client_mac)])
        )
        return udp_bootp

    def gen_discover(self):
        dhcp_discover = (
            self.gen_ether_ip_discover() /
            self.gen_udp_bootp() /
            DHCP(options=[
                ("message-type", "discover"),
                # MAY
                # ("param_req_list", PARAM_REQ_LIST),
                "end"
            ])
        )
        logger.debug('Generated discover.')
        logger.debug(dhcp_discover.summary())
        return dhcp_discover

    def send_discover(self):
        pkt = self.gen_discover()
        # Only when sending discover from RENEWING
        # The client records the local time at which the DHCPREQUEST
        # message is sent for computation of the lease expiration time
        # self.time_request = now()
        sendp(pkt)
        self.cur_discover_retry += 1
        logger.info('DHCPDISCOVER on %s to %s port %s' %
                    (self.iface, BROADCAST_ADDR, SERVER_PORT))
        logger.debug("Sent discover.")

    def select_offer(self):
        # TODO: algorithm to select offer
        logger.debug('Selecting offer.')
        pkt = self.offers[0]
        self.parse_Offer(pkt)

    def parse_Offer(self, pkt):
        logger.debug('Parsing offer.')
        logger.debug(pkt.summary())
        data = parse_response(pkt, debug=DEBUG)
        for key in data:
            setattr(self, key, data[key])

    def gen_request(self, server_mac=BROADCAST_MAC, server_ip=BROADCAST_ADDR,
                    client_ip=META_ADDR):
        # TODO: 3.1. SHOULD randomize the ordering of options
        dhcp_req = (
            self.gen_ether_ip_request(server_mac, server_ip, client_ip) /
            self.gen_udp_bootp() /
            DHCP(options=[
                ("message-type", "request"),
                # MAY
                # ("param_req_list", PARAM_REQ_LIST),
                # If the message is in response
                # to a DHCPOFFER, it MUST contain the corresponding Server
                # Identifier option and the Requested IP address
                ("server_id", self.server_id),
                ("requested_addr", self.client_ip_offered),
                "end"
            ])
        )
        logger.debug('Generated request.')
        logger.debug(dhcp_req.summary())
        return dhcp_req

    def send_request(self, server_mac=BROADCAST_MAC, server_ip=BROADCAST_ADDR,
                     client_ip=META_ADDR):
        pkt = self.gen_request(server_mac=server_mac, server_ip=server_ip,
                               client_ip=client_ip)
        sendp(pkt)
        self.time_sent_request = now()
        logger.info('DHCPREQUEST of %s on %s to %s port %s' %
                    (self.iface, self.client_ip_offered,
                     server_ip, self.server_port))
        logger.debug("Sent request.")

    def gen_decline(self):
        dhcp_decline = (
            self.gen_ether_ip_request(self.server_mac, self.server_ip,
                                      self.client_ip) /
            self.gen_udp_bootp() /
            DHCP(options=[
                ("message-type", "decline"),
                ("server_id", self.server_ip),
                ("requested_addr", self.client_ip_offered),
                "end"
            ])
        )
        logger.debug('Generated decline.')
        logger.debug(dhcp_decline.summary())
        return dhcp_decline

    def gen_release(self):
        dhcp_release = (
            self.gen_ether_ip_request(self.server_mac, self.server_ip,
                                      self.client_ip) /
            self.gen_udp_bootp() /
            DHCP(options=[
                ("message-type", "release"),
                ("server_id", self.server_id),
                "end"
            ])
        )
        logger.debug('Generated release.')
        logger.debug(dhcp_release.summary())
        return dhcp_release

    def gen_inform(self):
        dhcp_inform = (
            self.gen_ether_ip_request(self.server_mac, self.server_ip,
                                      self.client_ip) /
            self.gen_udp_bootp() /
            DHCP(options=[
                ("message-type", "inform"),
                # MAY
                # ("param_req_list", self.param_req_list)
                "end"
            ])
        )
        logger.debug('Generated inform.')
        logger.debug(dhcp_inform.summary())
        return dhcp_inform

    def info_net(self):
        logger.info('address %s', self.client_ip)
        logger.info('plen %s (%s)' % (self.subnet_mask_cidr, self.subnet_mask))
        logger.info('gateway %s', self.router)
        logger.info('server identifier %s', self.server_id)
        logger.info('nameserver %s', self.name_server)
        logger.info('domain name %s', self.domain)
        logger.info('lease time %s', self.lease_time)

    def parse_ACK(self, pkt):
        logger.debug("Parsing ACK.")
        logger.debug(pkt.summary())
        # FIXME: check the fields match the previously offered ones?
        data = parse_response(pkt, debug=DEBUG)
        for key in data:
            setattr(self, key, data[key])
        global LEASE_TIME
        if LEASE_TIME is not None:
            self.lease_time = LEASE_TIME
        self.client_ip = self.client_ip_offered
        # TODO: catch possible exception
        ipn = IPNetwork(self.client_ip + '/' + self.subnet_mask)
        self.subnet_mask_cidr = ipn.prefixlen
        self.info_net()

    def sanitize_net_values(self):
        try:
            ipn = IPNetwork(self.client_ip + '/' + self.subnet_mask)
        except AddrFormatError as e:
            # FIXME: add other errors
            logger.error(e)
        logger.debug('The IP address and network mask are sanitized')
        self.subnet_mask_cidr = ipn.prefixlen
        try:
            ipn = IPAddress(self.router)
        except AddrFormatError as e:
            # FIXME: add other errors
            logger.error(e)
        logger.debug('The gateway is sanitized')

    def set_net(self):
        from pyroute2 import IPRoute
        from pyroute2.netlink import NetlinkError
        ipr = IPRoute()
        # FIXME: bring iface up if down?
        index = ipr.link_lookup(ifname=self.iface)[0]
        try:
            ipr.addr('add', index, address=self.client_ip,
                     mask=self.subnet_mask_cidr)
        except NetlinkError as e:
            # FIXME: add other errors
            if ipr.get_addr(index=index)[0].\
                    get_attrs('IFA_ADDRESS')[0] == self.client_ip:
                logger.debug('Interface %s is already set to IP %s' %
                             (self.iface, self.client_ip))
            else:
                logger.error(e)
        else:
            logger.debug('Interface %s set to IP %s' %
                         (self.iface, self.client_ip))
        try:
            ipr.route('add', dst='0.0.0.0', gateway=self.router, oif=index)
        except NetlinkError as e:
            # FIXME: add other errors
            if ipr.get_routes(table=254)[0].\
                    get_attrs('RTA_GATEWAY')[0] == self.router:
                logger.debug('Default gateway is already set to %s' %
                             (self.router))
            else:
                logger.error(e)
        else:
            logger.debug('Default gateway set to %s', self.router)
        ipr.close()

    def set_timers(self):
        # RFC2131 4.4.1 The client records the lease expiration time as the sum of
        # the time at which the original request was sent and the duration of
        # the lease from the DHCPACK message.
        elapsed = (now() - self.time_sent_request).seconds
        self.lease_time -= elapsed
        if self.renewing_time is None:
            self.renewing_time = gen_renewing_time(self.lease_time)
        if self.rebinding_time is None:
            self.rebinding_time = gen_rebinding_time(self.lease_time)
        global RENEWING_TIME, REBINDING_TIME
        RENEWING_TIME = self.renewing_time
        REBINDING_TIME = self.rebinding_time
        logger.debug('LEASE_TIME %d' % self.lease_time)
        logger.info('Set RENEWING_TIME to %d and REBINDING_TIME to %d' %
                    (self.renewing_time, self.rebinding_time))

    def process_received_pkt(self, pkt):
        logger.debug("Received pkt.")
        logger.debug(pkt.summary())

    def process_received_ack(self, pkt):
        self.process_received_pkt(pkt)
        if is_ACK(pkt):
            self.parse_ACK(pkt)
            # TODO: if error in parse, go back to SELECTING
            # TODO: if address is taken (PING?) go to INIT and send DHCPDELINE
            logger.info('DHCPACK of %s from %s' %
                        (self.client_ip, self.server_ip))
            logger.debug('Transitioning to BOUND state.')
            raise self.BOUND()

    def process_received_nak(self, pkt):
        self.process_received_pkt(pkt)
        if is_NAK(pkt):
            logger.info('DHCPNAK of %s from %s' %
                        (self.client_ip, self.server_ip))
            logger.debug('Transitioning to INIT state.')
            raise self.INIT()

    def gen_retransmit_request_time(self):
        """In both RENEWING and REBINDING states, if the client receives no
           response to its DHCPREQUEST message, the client SHOULD wait one-half
           of the remaining time until T2 (in RENEWING state) and one-half of
           the remaining lease time (in REBINDING state), down to a minimum of
           60 seconds, before retransmitting the DHCPREQUEST message.
        """
        pass

    ###########################################################################
    # State machine
    ###########################################################################
    @ATMT.state(initial=1)
    def INIT(self):
        self.initialize()
        global DELAY_SELECTING
        # NOTE: this is not mentioned in the anonymity profile but RFC2131
        # The client SHOULD wait a random time between one and ten seconds to
        # desynchronize the use of DHCP at startup
        DELAY_SELECTING = gen_delay_selecting()
        logger.debug('waiting %s seconds before send discover' %
                     DELAY_SELECTING)
        logger.debug("In INIT state.")
        # NOTE: this state could transtion directly to SELECTING,
        # but it is implemented with a condition an action.
        # self.send(self.discover)
        # self.selecting=1
        # raise self.SELECTING()
        # in case INIT is reached from other state, initialize attributes
        # reset all variables, the first time the script run
        # this will be called twice.
        self.previous_state = self.current_state
        logger.debug('Previous state was %s', self.previous_state)
        self.current_state = 'INIT'

    # FIXME: why DELAY_SELECTING seems not to be set here?
    # @ATMT.timeout(INIT, DELAY_SELECTING)
    @ATMT.timeout(INIT, 1)
    # @ATMT.condition(INIT)
    def timeout_selecting(self):
        logger.debug("Transitioning to SELECTING.")
        raise self.SELECTING()

    @ATMT.action(timeout_selecting)
    def on_timeout_selecting(self):
        logger.debug("Action send discover.")
        self.send_discover()

    @ATMT.state()
    def SELECTING(self):
        self.previous_state = self.current_state
        self.current_state = 'SELECTING'
        logger.debug("In SELECTING state.")

    @ATMT.receive_condition(SELECTING)
    def receive_offer(self, pkt):
        logger.debug("Received pkt.")
        logger.debug(pkt.summary())
        if is_Offer(pkt):
            self.offers.append(pkt)
            logger.debug('Collected offer.')
            if len(self.offers) >= self.max_num_offers:
                self.select_offer()
                logger.debug("Selected offer.")
                raise self.REQUESTING()

    @ATMT.action(receive_offer)
    def on_select_offer(self):
        logger.debug('Action send request.')
        self.send_request()

    @ATMT.timeout(SELECTING, TIMEOUT_DISCOVER)
    def timeout_waiting_discover(self):
        # FIXME: implementation details are not mentioned in RFC
        logger.debug("Timeout discover.")
        logger.debug('Number of discover sent %s, number of max discovers %s' %
                     (self.cur_discover_retry, self.max_discover_retries))
        logger.debug('Number of offers received %s, number of max offers %s' %
                     (len(self.offers), self.max_num_offers))
        if self.cur_discover_retry >= self.max_discover_retries:
            logger.debug('Maximum number of retries reached.')
            if len(self.offers) < 1:
                logger.debug('No offer was received')
                logger.debug('Go to ERROR state.')
                raise self.ERROR()
        if len(self.offers) < self.max_num_offers:
            logger.debug('Naximum number of offers not reached.')
            logger.debug('Back to SELECTING state.')
            raise self.SELECTING()
        logger.debug('Maximum number of offers and discover reached,'
                     'should be in requesting')
        raise self.REQUESTING()

    @ATMT.action(timeout_waiting_discover)
    def on_retransmit_discover(self):
        # self.on_nothing()
        logger.debug('Number of discover sent %s, number of max discovers %s' %
                     (self.cur_discover_retry, self.max_discover_retries))
        if self.cur_discover_retry < self.max_discover_retries:
            logger.debug("Action send discover.")
            self.send_discover()

    @ATMT.state(error=1)
    def ERROR(self):
        self.previous_state = self.current_state
        self.current_state = 'ERROR'
        logger.info("In ERROR state.")
        raise self.END()

    # @ATMT.action(timeout_waiting_discover)
    # def on_ERROR(self):
    #  logger.debug("Action on ERROR.")

    @ATMT.state()
    def REQUESTING(self):
        self.previous_state = self.current_state
        self.current_state = 'REQUESTING'
        logger.debug("In REQUESTING state.")

    @ATMT.receive_condition(REQUESTING)
    def receive_ack_requesting(self, pkt):
        logger.info('rm')
        self.process_received_ack(pkt)
        # FIXME: check that address is not taken?
        # and otherwise send decline and go back to init?
        # this is a case that wouldn't happen in renewing and rebinding
        # RFC2131 4.4.1 The client SHOULD perform a
        # check on the suggested address to ensure that the address is not
        # already in use.  For example, if the client is on a network that
        # supports ARP, the client may issue an ARP request for the suggested
        # request.  When broadcasting an ARP request for the suggested address,
        # the client must fill in its own hardware address as the sender's
        # hardware address, and 0 as the sender's IP address, to avoid
        # confusing ARP caches in other hosts on the same subnet.  If the
        # network address appears to be in use, the client MUST send a
        # DHCPDECLINE message to the server. The client SHOULD broadcast an ARP
        # reply to announce the client's new IP address and clear any outdated
        # ARP cache entries in hosts on the client's subnet.

    @ATMT.receive_condition(REQUESTING)
    def receive_nak_requesting(self, pkt):
        self.process_received_nak(pkt)

    @ATMT.action(receive_ack_requesting)
    def on_bound(self):
        logger.debug('Action on bound: set timers.')
        # NOTE: not recording lease
        self.set_timers()
        self.sanitize_net_values()
        self.set_net()

    @ATMT.state()
    def BOUND(self):
        self.previous_state = self.current_state
        self.current_state = 'BOUND'
        logger.debug("In BOUND state.")
        logger.info('(%s) state changed %s -> bound' %
                    (self.iface, self.previous_state.lower()))

    @ATMT.timeout(BOUND, RENEWING_TIME)
    def renewing_time_expires(self):
        logger.debug("RENEWING_TIME %s expired.", RENEWING_TIME)
        logger.debug('Transitioning to RENEWING.')
        raise self.RENEWING()

    @ATMT.action(renewing_time_expires)
    def on_renewing_time_expired(self):
        logger.debug('Action on RENEWING_TIME expired:'
                     'send REQUEST to current server.')
        # send dhcprequest to current server
        self.send_request(server_ip=self.server_ip, server_mac=self.server_mac,
                          client_ip=self.client_ip)

    @ATMT.state()
    def RENEWING(self):
        self.previous_state = self.current_state
        self.current_state = 'RENEWING'
        logger.debug("In RENEWING state.")

    @ATMT.receive_condition(RENEWING)
    def receive_ack_renewing(self, pkt):
        self.process_received_ack(pkt)

    @ATMT.receive_condition(RENEWING)
    def receive_nak_renewing(self, pkt):
        self.process_received_nak(pkt)

    @ATMT.action(receive_ack_renewing)
    def on_renewing(self):
        logger.debug('Action on renewing: restart timers.')
        # NOTE: not recording lease
        # NOTE: no need to set_net again
        self.set_timers()

    @ATMT.timeout(RENEWING, REBINDING_TIME)
    def rebinding_time_expires(self):
        logger.debug("REBINDING_TIME expired.")
        logger.debug('Transitioning to REBINDING.')
        raise self.REBINDING()

    @ATMT.action(renewing_time_expires)
    def on_rebinding_time_expired(self):
        logger.debug('Action on REBINDING_TIME expired: broadcast REQUEST.')
        self.send_request(client_ip=self.client_ip)

    @ATMT.state()
    def REBINDING(self):
        self.previous_state = self.current_state
        self.current_state = 'REBINDING'
        logger.debug("In REBINDING state.")

    @ATMT.timeout(REBINDING, LEASE_TIME)
    def lease_expires(self):
        logger.debug("Lease expired.")
        logger.debug('Transitioning to INIT')
        # NOTE: not sending DHCPRELEASE to minimaze deanonymization
        # RFC2131 4.4.6 Note that the correct operation
        # of DHCP does not depend on the transmission of DHCPRELEASE messages.
        raise self.INIT()

    @ATMT.receive_condition(REBINDING)
    def receive_ack_rebinding(self, pkt):
        self.process_received_ack(pkt)

    @ATMT.receive_condition(REBINDING)
    def receive_nak_rebinding(self, pkt):
        self.process_received_nak(pkt)

    @ATMT.action(receive_ack_rebinding)
    def on_rebinding(self):
        logger.debug('Action on rebinding: restart timers.')
        # NOTE: not recording lease
        # NOTE: no need to set_net again
        self.set_timers()

    @ATMT.state(final=1)
    def END(self):
        self.previous_state = self.current_state
        self.current_state = 'END'
        logger.info("In END state.")
