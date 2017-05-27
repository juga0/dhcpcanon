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
from scapy.utils import str2mac
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
from timers import nowutc, gen_delay_selecting, gen_timeout_resend, \
    gen_timeout_request_renew, gen_timeout_request_rebind

logger = logging.getLogger(__name__)


class DHCPCAPFSM(Automaton):

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
                   client_port=None, client_mac=None, scriptfile=''):
        # RFC7844: an external program should randomize MAC prior
        # running this.
        logger.debug('Automaton parsing args.')
        # super(DHCPCAPFSM, self).parse_args(**kargs)
        logger.debug('initial constants names')
        logger.debug('%s', (LEASE_TIME, RENEWING_TIME, REBINDING_TIME,
                     DELAY_SELECTING, TIMEOUT_SELECTING,
                     TIMEOUT_REQUESTING, TIMEOUT_REQUEST_RENEWING,
                     TIMEOUT_REQUEST_REBINDING))
        # do not put interfaces in promiscuous mode
        self.debug_level = 3
        conf.sniff_promisc = conf.promisc = 0
        # conf.checkIPaddr = 0
        self.reset()
        self.client.iface = iface or conf.iface
        if client_mac is None:
            _, client_mac = get_if_raw_hwaddr(self.client.iface)
            self.client.client_mac = str2mac(client_mac)
        else:
            self.client.client_mac = client_mac
        self.client.server_port = server_port or SERVER_PORT
        self.client.client_port = client_port or CLIENT_PORT
        # capture filters
        self.socket_kargs = {
            'filter': 'udp and src port {0} and dst port {1}'
                      ' and ether dst {2}'.
                      format(self.client.server_port,
                             self.client.client_port,
                             self.client.client_mac)
            }
        self.script.scriptname = scriptfile
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        logger.debug('end automaton parsing args')

    def get_timeout(self, state, function):
        """ Workaround to change timeout values in the ATMT.timeout
        class method decorator.
        self.timeout format is:
        {'STATE': [
            (TIMEOUT0, <function foo>),
            (TIMEOUT1, <function bar>)),
            (None, None)
            ],
        }
        """

        state = STATES2NAMES[state]
        logger.debug('state %s, function %s', state, function)
        for timeout_fn_t in self.timeout[state]:
            # access the function name
            if timeout_fn_t[1] == function:
                logger.debug('timeout is %s', timeout_fn_t[0])
                return timeout_fn_t[0]

    def set_timeout(self, state, function, newtimeout):
        """ Workaround to change timeout values in the ATMT.timeout
        class method decorator.
        self.timeout format is:
        {'STATE': [
            (TIMEOUT0, <function foo>),
            (TIMEOUT1, <function bar>)),
            (None, None)
            ],
        }
        """

        state = STATES2NAMES[state]
        for timeout_fn_t in self.timeout[state]:
            # access the function name
            if timeout_fn_t[1] == function:
                # convert list to tuple to make it mutable
                timeout_l = list(timeout_fn_t)
                # modify the timeout
                timeout_l[0] = newtimeout
                # set the new timeoute to self.timeout
                i = self.timeout[state].index(timeout_fn_t)
                self.timeout[state][i] = tuple(timeout_l)
                logger.debug('Set state %s, function %s, to timeout %s',
                             state, function, newtimeout)

    def send_discover(self):
        assert(self.client)
        assert(self.current_state == STATE_INIT or
               self.current_state == STATE_SELECTING)
        pkt = self.client.gen_discover()
        sendp(pkt)
        # FIXME: check that this is correct,: all or only discover?
        if self.discover_attempts < MAX_ATTEMPTS_DISCOVER:
            self.discover_attempts += 1
        # FIXME: is this correct?
        timeout = gen_timeout_resend(self.discover_attempts)
        self.set_timeout(self.current_state,
                         self.timeout_selecting,
                         timeout)
        # logger.info('DHCPDISCOVER on %s to %s port %s' %
        #             (self.client.iface, self.client.server_mac,
        #              self.client.server_port))

    def select_offer(self):
        logger.debug('Selecting offer.')
        # TODO: algorithm to select offer
        pkt = self.offers[0]
        self.client.handle_offer(pkt)

    def send_request(self):
        assert(self.client)
        pkt = self.client.gen_request()
        sendp(pkt)
        self.time_sent_request = nowutc()
        logger.info('DHCPREQUEST of %s on %s to %s port %s' %
                    (self.client.iface, self.client.client_ip,
                     self.client.server_ip, self.client.server_port))

        # FIXME: check that this is correct,: all of only discover?
        # and if > MAX_DISCOVER_RETRIES?
        if self.request_attempts < MAX_ATTEMPTS_REQUEST:
            self.request_attempts *= 2
            logger.debug('Increased request attempts to %s',
                         self.request_attempts)
        if self.current_state == STATE_RENEWING:
            timeout_renewing = gen_timeout_request_renew(self.lease)
            self.set_timeout(self.current_state,
                             self.timeout_request_renewing,
                             timeout_renewing)
        elif self.current_state == STATE_REBINDING:
            timeout_rebinding = gen_timeout_request_rebind(self.lease)
            self.set_timeout(self.current_state,
                             self.timeout_request_rebinding,
                             timeout_rebinding)
        else:
            timeout_requesting = \
                gen_timeout_resend(self.request_attempts)
            self.set_timeout(self.current_state,
                             self.timeout_requesting,
                             timeout_requesting)

    def set_timers(self):
        logger.debug('setting timeouts')
        self.set_timeout(self.current_state,
                         self.renewing_time_expires,
                         self.client.lease.renewal_time)
        self.set_timeout(self.current_state,
                         self.rebinding_time_expires,
                         self.client.lease.rebinding_time)

    def process_received_ack(self, pkt):
        if isack(pkt):
            # FIXME: check the fields match the previously offered ones?
            self.event = self.client.handle_ack(pkt)
            self.client.lease.set_times(self.time_sent_request)
            # TODO: if error in parse, go back to SELECTING
            # TODO: if address is taken (PING?) go to INIT and send DHCPDELINE
            logger.info('DHCPACK of %s from %s' %
                        (self.client.client_ip, self.client.server_ip))
            return True
        return False

    def process_received_nak(self, pkt):
        if isnak(pkt):
            logger.info('DHCPNAK of %s from %s' %
                        (self.client_ip, self.server_ip))
            return True
        return False

    #################################################################
    # State machine
    #################################################################
    @ATMT.state(initial=1)
    def INIT(self):
        # in case INIT is reached from other state, initialize attributes
        # reset all variables.
        if self.current_state != STATE_PREINIT:
            self.reset()
        self.current_state = STATE_INIT
        # NOTE: not in RFC7844 but RFC2131
        # The client SHOULD wait a random time between one and ten
        #  seconds to desynchronize the use of DHCP at startup
        delay_selecting = gen_delay_selecting()
        self.set_timeout(self.current_state,
                         self.timeout_delay_selecting,
                         delay_selecting)

    @ATMT.timeout(INIT, DELAY_SELECTING)
    def timeout_delay_selecting(self):
        raise self.SELECTING()

    @ATMT.action(timeout_delay_selecting)
    def on_timeout_delay_selecting(self):
        self.send_discover()

    @ATMT.state()
    def SELECTING(self):
        self.current_state = STATE_SELECTING

    @ATMT.receive_condition(SELECTING)
    def receive_offer(self, pkt):
        if isoffer(pkt):
            self.offers.append(pkt)
            if len(self.offers) >= MAX_OFFERS_COLLECTED:
                self.select_offer()
                raise self.REQUESTING()
            else:
                # FIXME: neeeded?
                logger.debug('needed?')
                raise self.SELECTING()

    @ATMT.action(receive_offer)
    def on_select_offer(self):
        self.send_request()

    @ATMT.timeout(SELECTING, TIMEOUT_SELECTING)
    def timeout_selecting(self):
        # FIXME: implementation details are not mentioned in RFC
        if self.discover_attempts >= MAX_ATTEMPTS_DISCOVER:
            logger.debug('Maximum number of discover retries is %s'
                         ' and already sent %s',
                         MAX_ATTEMPTS_DISCOVER, self.discover_attempts)
            if len(self.offers) < 1:
                logger.debug('No offer was received')
                raise self.ERROR()
            else:
                # FIXME: correct?
                logger.debug('needed? Use the offers received')
                raise self.REQUESTING()
        # else self.discover_attempts < MAX_ATTEMPTS_DISCOVER
        if len(self.offers) < MAX_OFFERS_COLLECTED:
            logger.debug('needed? Naximum number of offers not reached')
            raise self.SELECTING()

        logger.debug('Naximum number of offers reached')
        raise self.REQUESTING()

    @ATMT.action(timeout_selecting)
    def on_retransmit_discover(self):
        self.send_discover()

    @ATMT.state(error=1)
    def ERROR(self):
        self.current_state = STATE_ERROR
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        raise self.END()

    # @ATMT.action(timeout_selecting)
    # def on_ERROR(self):
    #  logger.debug("Action on ERROR.")

    @ATMT.state()
    def REQUESTING(self):
        self.current_state = STATE_REQUESTING

    @ATMT.receive_condition(REQUESTING)
    def receive_ack_requesting(self, pkt):
        if self.process_received_ack(pkt):
            raise self.BOUND()

    @ATMT.receive_condition(REQUESTING)
    def receive_nak_requesting(self, pkt):
        if self.process_received_nak(pkt):
            raise self.INIT()

    @ATMT.action(receive_ack_requesting)
    def on_ack_requesting(self):
        # NOTE RFC78444: not recording lease
        self.set_timers()

    @ATMT.timeout(REQUESTING, TIMEOUT_REQUESTING)
    def timeout_requesting(self):
        # FIXME: implementation details are not mentioned in RFC
        if self.discover_requests >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of reuqest retries reached'
                         ' is %s and already sent %s',
                         MAX_ATTEMPTS_REQUEST, self.disover_requests)
            raise self.ERROR()
        raise self.REQUESTING()

    @ATMT.action(timeout_requesting)
    def on_retransmit_request(self):
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
        raise self.RENEWING()

    @ATMT.action(renewing_time_expires)
    def on_renewing_time_expires(self):
        # FIXME: udp
        self.send_request()

    @ATMT.state()
    def RENEWING(self):
        self.current_state = STATE_RENEWING
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()

    @ATMT.receive_condition(RENEWING)
    def receive_ack_renewing(self, pkt):
        if self.process_received_ack(pkt):
            raise self.BOUND()

    @ATMT.receive_condition(RENEWING)
    def receive_nak_renewing(self, pkt):
        if self.process_received_nak(pkt):
            raise self.INIT()

    @ATMT.action(receive_ack_renewing)
    def on_renewing(self):
        # NOTE: not recording lease
        self.client.lease.sanitize_net_values()
        self.client.lease.set_times(self.time_sent_request)
        self.set_timers()
        # FIXME: restart lease

    @ATMT.timeout(RENEWING, TIMEOUT_REQUEST_RENEWING)
    def timeout_request_renewing(self):
        # FIXME: implementation details are not mentioned in RFC
        if self.request_attempts >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of request retries renewing is'
                         ' %s, already sent %s.',
                         MAX_ATTEMPTS_REQUEST, self.request_attempts)
            raise self.ERROR()
        raise self.RENEWING()

    @ATMT.action(timeout_request_renewing)
    def on_retransmit_request_renewing(self):
        self.send_request()

    @ATMT.timeout(RENEWING, REBINDING_TIME)
    def rebinding_time_expires(self):
        raise self.REBINDING()

    @ATMT.action(rebinding_time_expires)
    def on_rebinding_time_expires(self):
        # broadcast
        self.send_request()

    @ATMT.state()
    def REBINDING(self):
        self.current_state = STATE_REBINDING
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()

    @ATMT.timeout(REBINDING, LEASE_TIME)
    def lease_expires(self):
        # NOTE: not sending DHCPRELEASE to minimaze deanonymization
        # RFC2131 4.4.6 Note that the correct operation
        # of DHCP does not depend on the transmission of DHCPRELEASE messages.
        raise self.STATE_INIT()

    @ATMT.receive_condition(REBINDING)
    def receive_ack_rebinding(self, pkt):
        if self.process_received_ack(pkt):
            raise self.BOUND()

    @ATMT.receive_condition(REBINDING)
    def receive_nak_rebinding(self, pkt):
        if self.process_received_nak(pkt):
            raise self.INIT()

    @ATMT.action(receive_ack_rebinding)
    def on_rebinding(self):
        # NOTE: not recording lease
        self.client.lease.sanitize_net_values()
        self.client.lease.set_times(self.time_sent_request)
        self.set_timers()
        # TODO: start new lease

    @ATMT.timeout(REBINDING, TIMEOUT_REQUEST_REBINDING)
    def timeout_request_rebinding(self):
        # FIXME: implementation details are not mentioned in RFC
        if self.request_attempts >= MAX_ATTEMPTS_REQUEST:
            logger.debug('Maximum number of request retries rebinding is'
                         ' %s, already sent %s.',
                         MAX_ATTEMPTS_REQUEST, self.request_attempts)
            raise self.ERROR()
        raise self.REBINDING()

    @ATMT.action(timeout_request_rebinding)
    def on_retransmit_request_rebinding(self):
        self.send_request()

    @ATMT.state(final=1)
    def END(self):
        self.current_state = STATE_END
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        self.reset()
