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
from scapy.automaton import Automaton, ATMT
from scapy.arch import get_if_raw_hwaddr
from scapy.utils import str2mac, mac2str
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.sendrecv import sendp
from scapy.config import conf

# These first constants are overwritten on run time,
# but ATMT.timeout is a class method and needs initial values
from constants import LEASE_TIME, RENEWING_TIME, REBINDING_TIME, \
    DELAY_SELECTING, TIMEOUT_SELECTING, TIMEOUT_REQUESTING, \
    TIMEOUT_REQUEST_RENEWING, TIMEOUT_REQUEST_REBINDING
from constants import SERVER_PORT, CLIENT_PORT, \
    MAX_ATTEMPTS_DISCOVER, MAX_ATTEMPTS_REQUEST, MAX_OFFERS_COLLECTED
from constants import STATE_PREINIT, STATE_INIT, STATE_SELECTING, \
    STATE_REQUESTING, STATE_BOUND, STATE_RENEWING, STATE_REBINDING, \
    STATE_END, STATE_ERROR, STATES2NAMES
from dhcpcap import DHCPCAP
from clientscript import ClientScript
from dhcpcaputils import isoffer, isnak, isack
from timers import nowutc, gen_renewing_time, gen_rebinding_time, \
    gen_delay_selecting, gen_timeout_resend, \
    gen_timeout_request_renew, gen_timeout_request_rebind

logger = logging.getLogger(__name__)


class DHCPCAPFSM(Automaton):

    def set_timeout(self, state, function, newtimeout):
        """ Workaround to change timeout values in the ATMT.timeout class method decorator.
        self.timeout format is:
        {'STATE': [
            (TIMEOUT0, <function foo>),
            (TIMEOUT1, <function bar>)),
            (None, None)
            ],
        }
        """
        state = STATES2NAMES[state]
        logger.debug('state %s, function %s, new timeout %s', state,
                     function, newtimeout)
        for atmt_timeout in self.timeout[state]:
            logger.debug('atmt_timeout %s', atmt_timeout)
            # access the function name
            if atmt_timeout[1] is not None:
                # convert list to tuple to make it mutable
                timeout_list = list(atmt_timeout)
                # modify the timeout
                timeout_list[0] = newtimeout
                # set the new timeoute to self.timeout
                i = self.timeout[state].index(atmt_timeout)
                self.timeout[state][i] = tuple(timeout_list)

    def reset(self, iface=None, client_mac=None, **kargs):
        logger.debug('Reseting attributes.')
        self.client = DHCPCAP(iface, client_mac)
        self.script = ClientScript()
        self.time_sent_request = None
        self.discover_attempts = 0
        self.request_attempts = 0
        self.current_state = STATE_PREINIT
        self.offers = list()

    def parse_args(self, iface=None, server_port=None,
                   client_port=None, client_mac=None, scriptfile='', **kargs):
        # RFC7844: an external program should randomize MAC prior running this.
        Automaton.parse_args(self, **kargs)
        self.reset()
        logger.debug('Automaton parsing args.')
        self.client.iface = iface or conf.iface
        if client_mac is None:
            _, client_mac = get_if_raw_hwaddr(self.client.iface)
            self.client.client_mac = str2mac(client_mac)
        else:
            self.client.client_mac = client_mac
        self.client.server_port = server_port or SERVER_PORT
        self.client.client_port = client_port or CLIENT_PORT
        self.script.scriptname = scriptfile
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()

    def master_filter(self, pkt):
        # logger.debug('pkt received %s', pkt.summary())
        # FIXME: this logger shows all the packets received,
        # Automaton methods has to be overwritten to don't capture
        # all the packets.
        # logger.debug(pkt.summary())
        if DHCP in pkt:
            logger.debug('Packet is DHCP')
            if pkt[BOOTP].chaddr[:6] == \
                    mac2str(self.client.client_mac):
                logger.debug('The packet dst is my MAC.')
                return True
                # FIXME, RFC7844: xid should not be used, but some
                # DHCP servers won't give a lease without it.
                # It should be the MAC address.
                # RFC2131: Any DHCPACK messages that arrive with an
                # 'xid' that does not match the 'xid' of the client's
                # DHCPREQUEST message are silently discarded.
                # pkt[BOOTP].xid == self.client_xid
                # )
        return False

    def send_discover(self):
        global TIMEOUT_SELECTING
        assert(self.client)
        assert(self.current_state == STATE_INIT or
               self.current_state == STATE_SELECTING)
        pkt = self.client.gen_discover()
        sendp(pkt)
        # FIXME: check that this is correct,: all or only discover?
        if self.discover_attempts < MAX_ATTEMPTS_DISCOVER:
            self.discover_attempts += 1
        # FIXME: is this correct?
        TIMEOUT_SELECTING = gen_timeout_resend(self.discover_attempts)
        self.set_timeout(self.current_state,
                             self.timeout_selecting,
                             TIMEOUT_SELECTING)
        logger.info('DHCPDISCOVER on %s to %s port %s' %
                    (self.client.iface, self.client.server_mac,
                     self.client.server_port))

    def select_offer(self):
        logger.debug('Selecting offer.')
        # TODO: algorithm to select offer
        pkt = self.offers[0]
        self.client.handle_offer(pkt)

    def send_request(self):
        global TIMEOUT_REQUESTING, TIMEOUT_REQUEST_RENEWING
        global TIMEOUT_REQUEST_REBINDING
        assert(self.client)
        pkt = self.client.gen_request()
        sendp(pkt)
        self.time_sent_request = nowutc()

        # FIXME: check that this is correct,: all of only discover?
        # and if > MAX_DISCOVER_RETRIES?
        if self.request_attempts < MAX_ATTEMPTS_REQUEST:
            self.request_attempts *= 2
        if self.current_state == STATE_RENEWING:
            TIMEOUT_REQUEST_RENEWING = \
                gen_timeout_request_renew(self.lease)
            self.set_timeout(self.current_state,
                                 self.timeout_request_renewing,
                                 TIMEOUT_REQUEST_RENEWING)
        elif self.current_state == STATE_REBINDING:
            TIMEOUT_REQUEST_REBINDING = \
                gen_timeout_request_rebind(self.lease)
            self.set_timeout(self.current_state,
                                 self.timeout_request_rebinding,
                                 TIMEOUT_REQUEST_REBINDING)
        else:
            TIMEOUT_REQUESTING = \
                gen_timeout_resend(self.request_attempts)
            self.set_timeout(self.current_state,
                                 self.timeout_requesting,
                                 TIMEOUT_REQUESTING)
        logger.info('DHCPREQUEST of %s on %s to %s port %s' %
                    (self.client.iface, self.client.client_ip,
                     self.client.server_ip, self.client.server_port))

    def set_timers(self):
        global RENEWING_TIME, REBINDING_TIME, LEASE_TIME
        # global TIMEOUT_REQUEST_RENEWING
        # global TIMEOUT_REQUEST_REBINDING
        # RFC2131 4.4.1 The client records the lease expiration time
        # as the sum of the time at which the original request was
        # sent and the duration of the lease from the DHCPACK message.
        elapsed = (nowutc() - self.time_sent_request).seconds
        self.client.lease.renewal_time = \
            gen_renewing_time(self.client.lease.lease_time, elapsed)
        self.client.lease.rebinding_time = \
            gen_rebinding_time(self.client.lease.lease_time, elapsed)
        LEASE_TIME = self.client.lease.lease_time
        RENEWING_TIME = self.client.lease.renewal_time
        REBINDING_TIME = self.client.lease.rebinding_time
        # TIMEOUT_REQUEST_RENEWING = \
        #     gen_timeout_request_renew(self.client.lease)
        # TIMEOUT_REQUEST_REBINDING = \
        #     gen_timeout_request_rebind(self.client.lease)
        self.set_timeout(self.current_state,
                             self.renewing_time_expires,
                             RENEWING_TIME)
        self.set_timeout(self.current_state,
                             self.rebinding_time_expires,
                             REBINDING_TIME)
        logger.debug('LEASE_TIME %d' % LEASE_TIME)
        logger.info('RENEWING_TIME: %d, REBINDING_TIME: %d' %
                    (RENEWING_TIME, REBINDING_TIME))

    def process_received_ack(self, pkt):
        logger.debug('pkt received %s', pkt.summary())
        if isack(pkt):
            # FIXME: check the fields match the previously offered ones?
            self.event = self.client.handle_ack(pkt)
            # TODO: if error in parse, go back to SELECTING
            # TODO: if address is taken (PING?) go to INIT and send DHCPDELINE
            logger.info('DHCPACK of %s from %s' %
                        (self.client.client_ip, self.client.server_ip))
            return True
        return False

    def process_received_nak(self, pkt):
        logger.debug('pkt received %s', pkt.summary())
        if isnak(pkt):
            logger.info('DHCPNAK of %s from %s' %
                        (self.client_ip, self.server_ip))
            logger.debug('Transitioning to INIT state.')
            return True
        return False

    #################################################################
    # State machine
    #################################################################
    @ATMT.state(initial=1)
    def INIT(self):
        logger.debug('state %s', self.state)
        global DELAY_SELECTING
        # in case INIT is reached from other state, initialize attributes
        # reset all variables.
        if self.current_state != STATE_PREINIT:
            self.reset()
        # NOTE: not in RFC7844 but RFC2131
        # The client SHOULD wait a random time between one and ten
        #  seconds to desynchronize the use of DHCP at startup
        logger.debug("In INIT state.")
        logger.debug('Previous state was %s', self.current_state)
        self.current_state = STATE_INIT
        DELAY_SELECTING = gen_delay_selecting()
        self.set_timeout(self.current_state,
                             self.timeout_delay_selecting,
                             DELAY_SELECTING)
        logger.debug('waiting %s seconds before send discover' %
                     DELAY_SELECTING)

    @ATMT.timeout(INIT, DELAY_SELECTING)
    def timeout_delay_selecting(self):
        logger.debug("Timeout on delay selectiog, transitioning to SELECTING.")
        raise self.SELECTING()

    @ATMT.action(timeout_delay_selecting)
    def on_timeout_delay_selecting(self):
        logger.debug("Action on delay selecting timeout, send discover.")
        self.send_discover()

    @ATMT.state()
    def SELECTING(self):
        self.current_state = STATE_SELECTING
        logger.debug("In SELECTING state.")

    @ATMT.receive_condition(SELECTING)
    def receive_offer(self, pkt):
        logger.debug("On SELECTING receive condition: receive offer.")
        logger.debug(pkt.summary())
        if isoffer(pkt):
            self.offers.append(pkt)
            if len(self.offers) >= MAX_OFFERS_COLLECTED:
                self.select_offer()
                logger.debug("Selected offer.")
                raise self.REQUESTING()

    @ATMT.action(receive_offer)
    def on_select_offer(self):
        logger.debug('Action on receive offer, send request.')
        self.send_request()

    @ATMT.timeout(SELECTING, TIMEOUT_SELECTING)
    def timeout_selecting(self):
        # FIXME: implementation details are not mentioned in RFC
        logger.debug("Timeout waiting offer %s.",
                     TIMEOUT_SELECTING)
        logger.debug('Number of discover sent %s, number of max discovers %s' %
                     (self.discover_attempts, MAX_ATTEMPTS_DISCOVER))
        logger.debug('Number of offers received %s, number of max offers %s' %
                     (len(self.offers), MAX_OFFERS_COLLECTED))
        if self.discover_attempts >= self.MAX_ATTEMPTS_DISCOVER:
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

    @ATMT.action(timeout_selecting)
    def on_retransmit_discover(self):
        logger.debug('Number of discover sent %s, number of max discovers %s' %
                     (self.discover_attempts, self.MAX_ATTEMPTS_DISCOVER))
        if self.discover_attempts < self.MAX_ATTEMPTS_DISCOVER:
            logger.debug("Action send discover.")
            self.send_discover()

    @ATMT.state(error=1)
    def ERROR(self):
        self.current_state = STATE_ERROR
        logger.info("In ERROR state.")
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        raise self.END()

    # @ATMT.action(timeout_selecting)
    # def on_ERROR(self):
    #  logger.debug("Action on ERROR.")

    @ATMT.state()
    def REQUESTING(self):
        self.current_state = STATE_REQUESTING
        logger.debug("In REQUESTING state.")

    @ATMT.receive_condition(REQUESTING)
    def receive_ack_requesting(self, pkt):
        logger.info('On receive conditon REQUESTING, receive ACK.')
        if self.process_received_ack(pkt):
            logger.debug('Transitioning to BOUND state.')
            raise self.BOUND()

    @ATMT.receive_condition(REQUESTING)
    def receive_nak_requesting(self, pkt):
        logger.info('On receive conditon REQUESTING, receive NAK.')
        if self.process_received_nak(pkt):
            logger.debug('Transitioning to INIT state.')
            raise self.INIT()

    @ATMT.action(receive_ack_requesting)
    def on_ack_requesting(self):
        logger.debug('Action on receive ACK requesting, set timers.')
        # NOTE RFC78444: not recording lease
        self.set_timers()
        self.client.lease.sanitize_net_values()

    @ATMT.timeout(REQUESTING, TIMEOUT_REQUESTING)
    def timeout_requesting(self):
        # FIXME: implementation details are not mentioned in RFC
        logger.debug("Timeout on REQUESTING %s.",
                     TIMEOUT_REQUESTING)
        if self.discover_requests >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of retries reached.')
            raise self.ERROR()
        raise self.REQUESTING()

    @ATMT.action(timeout_requesting)
    def on_retransmit_request(self):
        logger.debug('Number of request sent %s, number of max requests %s' %
                     (self.request_attempts, MAX_ATTEMPTS_REQUEST))
        if self.request_attempts < MAX_ATTEMPTS_REQUEST:
            logger.debug("Action resend request.")
            self.send_request()

    @ATMT.state()
    def BOUND(self):
        logger.info('(%s) state changed %s -> bound' %
                    (self.client.iface,
                     STATES2NAMES[self.current_state]))
        self.current_state = STATE_BOUND
        self.script.script_init(self.client.lease, self.current_state)
        # TODO: go daemon?
        self.script.script_go()

    @ATMT.timeout(BOUND, RENEWING_TIME)
    def renewing_time_expires(self):
        logger.debug("Timeout RENEWING_TIME %s,"
                     ' transitioning to RENEWING.', RENEWING_TIME)
        raise self.RENEWING()

    @ATMT.action(renewing_time_expires)
    def on_renewing_time_expires(self):
        logger.debug('Action on RENEWING_TIME tiemout:'
                     'send REQUEST to current server.')
        # FIXME: udp
        self.send_request()

    @ATMT.state()
    def RENEWING(self):
        self.previous_state = self.current_state
        self.current_state = STATE_RENEWING
        logger.debug("In RENEWING state.")
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()

    @ATMT.receive_condition(RENEWING)
    def receive_ack_renewing(self, pkt):
        logger.debug('On receive ACK RENEWING.')
        if self.process_received_ack(pkt):
            logger.debug('Transitioning to BOUND state.')
            raise self.BOUND()

    @ATMT.receive_condition(RENEWING)
    def receive_nak_renewing(self, pkt):
        logger.debug('On receive NAK RENEWING.')
        if self.process_received_nak(pkt):
            logger.debug('Transitioning to INIT state.')
            raise self.INIT()

    @ATMT.action(receive_ack_renewing)
    def on_renewing(self):
        logger.debug('Action on receive ACK renewing: restart timers.')
        # NOTE: not recording lease
        self.set_timers()
        # FIXME: restart lease

    @ATMT.timeout(RENEWING, TIMEOUT_REQUEST_RENEWING)
    def timeout_request_renewing(self):
        # FIXME: implementation details are not mentioned in RFC
        logger.debug("Timeout on REQUEST RENEWING %s.",
                     TIMEOUT_REQUEST_RENEWING)
        if self.request_attempts >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of retries reached.')
            raise self.ERROR()
        raise self.RENEWING()

    @ATMT.action(timeout_request_renewing)
    def on_retransmit_request_renewing(self):
        logger.debug('Number of request sent %s, number of max requests %s' %
                     (self.request_attempts, MAX_ATTEMPTS_REQUEST))
        if self.request_attempts < MAX_ATTEMPTS_REQUEST:
            logger.debug("Action resend request.")
            self.send_request()

    @ATMT.timeout(RENEWING, REBINDING_TIME)
    def rebinding_time_expires(self):
        logger.debug("Timeout REBINDING_TIME %s", REBINDING_TIME)
        logger.debug('Transitioning to REBINDING.')
        raise self.REBINDING()

    @ATMT.action(rebinding_time_expires)
    def on_rebinding_time_expires(self):
        logger.debug('Action on REBINDING_TIME timeout: broadcast REQUEST.')
        # broadcast
        self.send_request()

    @ATMT.state()
    def REBINDING(self):
        self.previous_state = self.current_state
        self.current_state = STATE_REBINDING
        logger.debug("In REBINDING state.")
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()

    @ATMT.timeout(REBINDING, LEASE_TIME)
    def lease_expires(self):
        logger.debug("Lease timeout. Transitioning to INIT")
        # NOTE: not sending DHCPRELEASE to minimaze deanonymization
        # RFC2131 4.4.6 Note that the correct operation
        # of DHCP does not depend on the transmission of DHCPRELEASE messages.
        raise self.STATE_INIT()

    @ATMT.receive_condition(REBINDING)
    def receive_ack_rebinding(self, pkt):
        if self.process_received_ack(pkt):
            logger.debug('Transitioning to BOUND state.')
            raise self.BOUND()

    @ATMT.receive_condition(REBINDING)
    def receive_nak_rebinding(self, pkt):
        if self.process_received_nak(pkt):
            logger.debug('Transitioning to INIT state.')
            raise self.INIT()

    @ATMT.action(receive_ack_rebinding)
    def on_rebinding(self):
        logger.debug('Action on rebinding: restart timers.')
        # NOTE: not recording lease
        self.set_timers()
        # TODO: start new lease

    @ATMT.timeout(REBINDING, TIMEOUT_REQUEST_REBINDING)
    def timeout_request_rebinding(self):
        # FIXME: implementation details are not mentioned in RFC
        logger.debug("Timeout on REQUEST REBINDING %s.",
                     TIMEOUT_REQUEST_REBINDING)
        if self.request_attempts >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of retries reached.')
            raise self.ERROR()
        raise self.REBINDING()

    @ATMT.action(timeout_request_rebinding)
    def on_retransmit_request_rebinding(self):
        logger.debug('Number of request sent %s, number of max requests %s' %
                     (self.request_attempts, MAX_ATTEMPTS_REQUEST))
        if self.request_attempts < MAX_ATTEMPTS_REQUEST:
            logger.debug("Action resend request.")
            self.send_request()

    @ATMT.state(final=1)
    def END(self):
        self.current_state = STATE_END
        logger.info("In END state.")
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        self.reset()
