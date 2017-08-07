# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""DCHP client implementation of the Anonymity Profiles [:rfc:`7844`]."""
from __future__ import absolute_import, unicode_literals

import logging

from netaddr import AddrFormatError
from scapy.arch import get_if_raw_hwaddr
from scapy.automaton import ATMT, Automaton
from scapy.config import conf
from scapy.sendrecv import sendp
from scapy.utils import str2mac

from .clientscript import ClientScript
from .constants import (CLIENT_PORT, DELAY_SELECTING, FSM_ATTRS, LEASE_TIME,
                        MAX_ATTEMPTS_DISCOVER, MAX_ATTEMPTS_REQUEST,
                        MAX_OFFERS_COLLECTED, REBINDING_TIME, RENEWING_TIME,
                        SERVER_PORT, STATE_BOUND, STATE_END, STATE_ERROR,
                        STATE_INIT, STATE_PREINIT, STATE_REBINDING,
                        STATE_RENEWING, STATE_REQUESTING, STATE_SELECTING,
                        STATES2NAMES, TIMEOUT_REQUEST_REBINDING,
                        TIMEOUT_REQUEST_RENEWING, TIMEOUT_REQUESTING,
                        TIMEOUT_SELECTING)
from .dhcpcap import DHCPCAP
from .dhcpcaputils import isack, isnak, isoffer
from .timers import (gen_delay_selecting, gen_timeout_request_rebind,
                     gen_timeout_request_renew, gen_timeout_resend, nowutc)

logger = logging.getLogger(__name__)


class DHCPCAPFSM(Automaton):
    """DHCP client Finite State Machine (FSM)."""

    def dict_self(self):
        """Return the self object attributes not inherited as dict."""
        return {k: v for k, v in self.__dict__.items() if k in FSM_ATTRS}

    def __str__(self):
        return str(self.dict_self())

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def reset(self, iface=None, client_mac=None, xid=None):
        """Reset object attributes when state is INIT."""
        logger.debug('Reseting attributes.')
        if iface is None:
            iface = conf.iface
        if client_mac is None:
            # scapy for python 3 returns byte, not tuple
            tempmac = get_if_raw_hwaddr(iface)
            if isinstance(tempmac, tuple) and len(tempmac) == 2:
                mac = tempmac[1]
            else:
                mac = tempmac
            client_mac = str2mac(mac)
        self.client = DHCPCAP(iface=iface, client_mac=client_mac, xid=xid)
        self.script = ClientScript()
        self.time_sent_request = None
        self.discover_attempts = 0
        self.request_attempts = 0
        self.current_state = STATE_PREINIT
        self.offers = list()

    def __init__(self, iface=None, server_port=None,
                 client_port=None, client_mac=None, xid=None,
                 scriptfile=None, delay_before_selecting=None,
                 timeout_select=None, debug_level=5, *args, **kargs):
        """Overwrites Automaton __init__ method.

        [ :rfc:`7844#section-3.4` ] ::
            If the hardware address is reset to a new
            randomized value, the DHCP client SHOULD use the new randomized
            value in the DHCP messages

        """
        logger.debug('Inizializating FSM.')
        super(DHCPCAPFSM, self).__init__(*args, **kargs)
        self.debug_level = debug_level
        self.delay_before_selecting = delay_before_selecting
        self.timeout_select = timeout_select
        self.reset(iface, client_mac, xid)
        self.client.server_port = server_port or SERVER_PORT
        self.client.client_port = client_port or CLIENT_PORT
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
        logger.debug('FSM thread id: %s.', self.threadid)

    def get_timeout(self, state, function):
        """Workaround to get timeout in the ATMT.timeout class method."""
        state = STATES2NAMES[state]
        for timeout_fn_t in self.timeout[state]:
            # access the function name
            if timeout_fn_t[1] is not None and \
               timeout_fn_t[1].atmt_condname == function.atmt_condname:
                logger.debug('Timeout for state %s, function %s, is %s',
                             state, function.atmt_condname, timeout_fn_t[0])
                return timeout_fn_t[0]
        return None

    def set_timeout(self, state, function, newtimeout):
        """
        Workaround to change timeout values in the ATMT.timeout class method.

        self.timeout format is::

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
            if timeout_fn_t[1] is not None and \
               timeout_fn_t[1].atmt_condname == function.atmt_condname:
                # convert list to tuple to make it mutable
                timeout_l = list(timeout_fn_t)
                # modify the timeout
                timeout_l[0] = newtimeout
                # set the new timeoute to self.timeout
                i = self.timeout[state].index(timeout_fn_t)
                self.timeout[state][i] = tuple(timeout_l)
                logger.debug('Set state %s, function %s, to timeout %s',
                             state, function.atmt_condname, newtimeout)

    def send_discover(self):
        """Send discover."""
        assert self.client
        assert self.current_state == STATE_INIT or \
            self.current_state == STATE_SELECTING
        pkt = self.client.gen_discover()
        sendp(pkt)
        # FIXME:20 check that this is correct,: all or only discover?
        if self.discover_attempts < MAX_ATTEMPTS_DISCOVER:
            self.discover_attempts += 1
        timeout = gen_timeout_resend(self.discover_attempts)
        self.set_timeout(self.current_state,
                         self.timeout_selecting,
                         timeout)
        # logger.info('DHCPDISCOVER on %s to %s port %s' %
        #             (self.client.iface, self.client.server_mac,
        #              self.client.server_port)))

    def select_offer(self):
        """Select an offer from the offers received.

        [:rfc:`2131#section-4.2`]::

            DHCP clients are free to use any strategy in selecting a DHCP
            server among those from which the client receives a DHCPOFFER.

        [:rfc:`2131#section-4.4.1`]::

            The time
            over which the client collects messages and the mechanism used to
            select one DHCPOFFER are implementation dependent.

        Nor [:rfc:`7844`] nor [:rfc:`2131`] specify the algorithm.
        Here, currently the first offer is selected.

        .. todo::

           - Check other implementations algorithm to select offer.

        """
        logger.debug('Selecting offer.')
        pkt = self.offers[0]
        self.client.handle_offer(pkt)

    def send_request(self):
        """Send request.

        [:rfc:`2131#section-3.1`]::

        a client retransmitting as described in section 4.1 might retransmit
        the DHCPREQUEST message four times, for a total delay of 60 seconds

        .. todo::

           - The maximum number of retransmitted REQUESTs is per state or in
             total?
           - Are the retransmitted REQUESTs independent to the retransmitted
             DISCOVERs?

        """
        assert self.client
        if self.current_state == STATE_BOUND:
            pkt = self.client.gen_request_unicast()
        else:
            pkt = self.client.gen_request()
        sendp(pkt)
        logger.debug('Modifying FSM obj, setting time_sent_request.')
        self.time_sent_request = nowutc()
        logger.info('DHCPREQUEST of %s on %s to %s port %s',
                    self.client.iface, self.client.client_ip,
                    self.client.server_ip, self.client.server_port)

        # NOTE: see previous TODO, maybe the MAX_ATTEMPTS_REQUEST needs to be
        # calculated per state.
        if self.request_attempts < MAX_ATTEMPTS_REQUEST:
            self.request_attempts *= 2
            logger.debug('Increased request attempts to %s',
                         self.request_attempts)
        if self.current_state == STATE_RENEWING:
            timeout_renewing = gen_timeout_request_renew(self.client.lease)
            self.set_timeout(self.current_state,
                             self.timeout_request_renewing,
                             timeout_renewing)
        elif self.current_state == STATE_REBINDING:
            timeout_rebinding = gen_timeout_request_rebind(self.client.lease)
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
        """Set renewal, rebinding times."""
        logger.debug('setting timeouts')
        self.set_timeout(self.current_state,
                         self.renewing_time_expires,
                         self.client.lease.renewal_time)
        self.set_timeout(self.current_state,
                         self.rebinding_time_expires,
                         self.client.lease.rebinding_time)

    def process_received_ack(self, pkt):
        """Process a received ACK packet.

        Not specifiyed in [:rfc:`7844`].
        Probe the offered IP in [:rfc:`2131#section-2.2.`]::

            the allocating
            server SHOULD probe the reused address before allocating the
            address, e.g., with an ICMP echo request, and the client SHOULD
            probe the newly received address, e.g., with ARP.

            The client SHOULD broadcast an ARP
            reply to announce the client's new IP address and clear any
            outdated ARP cache entries in hosts on the client's subnet.

        It is also not specifiyed in [:rfc:`7844`] nor [:rfc:`2131`] how to
        check that the offered IP is valid.

        .. todo::
           - Check that nor ``dhclient`` nor ``systemd-networkd`` send an ARP.
           - Check how other implementations check that the ACK paremeters
             are valid, ie, if the ACK fields match the fields in the OFFER.
           - Check to which state the client should go back to when the
             offered parameters are not valid.

        """
        if isack(pkt):
            try:
                self.event = self.client.handle_ack(pkt,
                                                    self.time_sent_request)
            except AddrFormatError as err:
                logger.error(err)
                # NOTE: see previous TODO, maybe should go back to other state.
                raise self.SELECTING()
            # NOTE: see previous TODO, not checking address with ARP.
            logger.info('DHCPACK of %s from %s' %
                        (self.client.client_ip, self.client.server_ip))
            return True
        return False

    def process_received_nak(self, pkt):
        """Process a received NAK packet."""
        if isnak(pkt):
            logger.info('DHCPNAK of %s from %s',
                        self.client.client_ip, self.client.server_ip)
            return True
        return False

    #################################################################
    # State machine
    #################################################################

    # STATES
    #########

    @ATMT.state(initial=1)
    def INIT(self):
        """INIT state.

        [:rfc:`2131#section-4.4.1`]::

            The client SHOULD wait a random time between one and ten
            seconds to desynchronize the use of DHCP at startup

        .. todo::
           - The initial delay is implemented, but probably is not in other
             implementations. Check what other implementations do.
        """
        # NOTE: in case INIT is reached from other state, initialize attributes
        # reset all variables.
        logger.debug('In state: INIT')
        if self.current_state is not STATE_PREINIT:
            self.reset()
        self.current_state = STATE_INIT
        # NOTE: see previous TODO, maybe this is not needed.
        if self.delay_before_selecting is None:
            delay_before_selecting = gen_delay_selecting()
        else:
            delay_before_selecting = self.delay_before_selecting
        self.set_timeout(self.current_state,
                         self.timeout_delay_before_selecting,
                         delay_before_selecting)
        if self.timeout_select is not None:
            self.set_timeout(STATE_SELECTING,
                             self.timeout_selecting,
                             self.timeout_select)

    @ATMT.state()
    def SELECTING(self):
        """SELECTING state."""
        logger.debug('In state: SELECTING')
        self.current_state = STATE_SELECTING

    @ATMT.state()
    def REQUESTING(self):
        """REQUESTING state."""
        logger.debug('In state: REQUESTING')
        self.current_state = STATE_REQUESTING

    @ATMT.state()
    def BOUND(self):
        """BOUND state."""
        logger.debug('In state: BOUND')
        logger.info('(%s) state changed %s -> bound', self.client.iface,
                    STATES2NAMES[self.current_state])
        self.current_state = STATE_BOUND
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        # TODO: go daemon?

    @ATMT.state()
    def RENEWING(self):
        """RENEWING state."""
        logger.debug('In state: RENEWING')
        self.current_state = STATE_RENEWING
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()

    @ATMT.state()
    def REBINDING(self):
        """REBINDING state."""
        logger.debug('In state: REBINDING')
        self.current_state = STATE_REBINDING
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()

    @ATMT.state(final=1)
    def END(self):
        """END state."""
        logger.debug('In state: END')
        self.current_state = STATE_END
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        self.reset()

    @ATMT.state(error=1)
    def ERROR(self):
        """ERROR state."""
        logger.debug('In state: ERROR')
        self.current_state = STATE_ERROR
        self.script.script_init(self.client.lease, self.current_state)
        self.script.script_go()
        raise self.END()

    # TIMEOUTS
    ###########

    # TIMEOUTS: retransmissions
    # ----------------------------
    @ATMT.timeout(INIT, DELAY_SELECTING)
    def timeout_delay_before_selecting(self):
        """Timeout delay selecting in INIT state."""
        logger.debug('C1:T. In %s, timeout delay selecting, raise SELECTING',
                     self.current_state)
        raise self.SELECTING()

    @ATMT.timeout(SELECTING, TIMEOUT_SELECTING)
    def timeout_selecting(self):
        """Timeout of selecting on SELECTING state.

        Not specifiyed in [:rfc:`7844`].
        See comments in :func:`dhcpcapfsm.DHCPCAPFSM.timeout_request`.

        """
        logger.debug('C2.1: T In %s, timeout receiving response to select.',
                     self.current_state)

        if len(self.offers) >= MAX_OFFERS_COLLECTED:
            logger.debug('C2.2: T Maximum number of offers reached, '
                         'raise REQUESTING.')
            raise self.REQUESTING()

        if self.discover_attempts >= MAX_ATTEMPTS_DISCOVER:
            logger.debug('C2.3: T Maximum number of discover retries is %s'
                         ' and already sent %s.',
                         MAX_ATTEMPTS_DISCOVER, self.discover_attempts)
            if len(self.offers) <= 0:
                logger.debug('C2.4: T. But no OFFERS where received, '
                             'raise ERROR.')
                raise self.ERROR()
            logger.debug('C2.4: F. But there is some OFFERS, '
                         'raise REQUESTING.')
            raise self.REQUESTING()

        logger.debug('C2.2: F. Still not received all OFFERS, but not '
                     'max # attemps reached, raise SELECTING.')
        raise self.SELECTING()

    @ATMT.timeout(REQUESTING, TIMEOUT_REQUESTING)
    def timeout_requesting(self):
        """Timeout requesting in REQUESTING state.

        Not specifiyed in [:rfc:`7844`]

        [:rfc:`2131#section-3.1`]::

            might retransmit the
            DHCPREQUEST message four times, for a total delay of 60 seconds

        """
        logger.debug("C3.2: T. In %s, timeout receiving response to request, ",
                     self.current_state)
        if self.discover_requests >= MAX_ATTEMPTS_REQUEST:
            logger.debug('C2.3: T. Maximum number %s of REQUESTs '
                         'reached, already sent %s, raise ERROR.',
                         MAX_ATTEMPTS_REQUEST, self.disover_requests)
            raise self.ERROR()
        logger.debug("C2.3: F. Maximum number of REQUESTs retries not reached,"
                     "raise REQUESTING.")
        raise self.REQUESTING()

    @ATMT.timeout(RENEWING, TIMEOUT_REQUEST_RENEWING)
    def timeout_request_renewing(self):
        """Timeout of renewing on RENEWING state.

        Same comments as in
        :func:`dhcpcapfsm.DHCPCAPFSM.timeout_requesting`.

        """
        logger.debug("C5.2:T In %s, timeout receiving response to request.",
                     self.current_state)
        if self.request_attempts >= MAX_ATTEMPTS_REQUEST:
            logger.debug('C2.3: T Maximum number %s of REQUESTs '
                         'reached, already sent %s, wait to rebinding time.',
                         MAX_ATTEMPTS_REQUEST, self.disover_requests)
            # raise self.ERROR()
        logger.debug("C2.3: F. Maximum number of REQUESTs retries not reached,"
                     "raise RENEWING.")
        raise self.RENEWING()

    @ATMT.timeout(REBINDING, TIMEOUT_REQUEST_REBINDING)
    def timeout_request_rebinding(self):
        """Timeout of request rebinding on REBINDING state.

        Same comments as in
        :func:`dhcpcapfsm.DHCPCAPFSM.timeout_requesting`.

        """
        logger.debug("C6.2:T In %s, timeout receiving response to request.",
                     self.current_state)
        if self.request_attempts >= MAX_ATTEMPTS_REQUEST:
            logger.debug('C.2.3: T. Maximum number %s of REQUESTs '
                         'reached, already sent %s, wait lease time expires.',
                         MAX_ATTEMPTS_REQUEST, self.disover_requests)
            # raise self.ERROR()
        logger.debug("C2.3: F. Maximum number of REQUESTs retries not reached,"
                     "raise REBINDING.")
        raise self.REBINDING()

    # TIMEOUTS: timers
    # -----------------

    @ATMT.timeout(BOUND, RENEWING_TIME)
    def renewing_time_expires(self):
        """Timeout renewing time (T1), transition to RENEWING."""
        logger.debug("C4. Timeout renewing time, in BOUND state, "
                     "raise RENEWING.")
        raise self.RENEWING()

    @ATMT.timeout(RENEWING, REBINDING_TIME)
    def rebinding_time_expires(self):
        """Timeout rebinding time (T2), transition to REBINDING."""
        logger.debug("C5.3. Timeout rebinding time, in RENEWING state, "
                     "raise REBINDING.")
        raise self.REBINDING()

    @ATMT.timeout(REBINDING, LEASE_TIME)
    def lease_expires(self):
        """Timeout lease time, transition to INIT.

        Not sending DHCPRELEASE to minimize deanonymization

        [:rfc:`2131#section-4.4.6`]::

            Note that the correct operation
            of DHCP does not depend on the transmission of DHCPRELEASE.

        """
        logger.debug("C6.3. Timeout lease time, in REBINDING state, "
                     "raise INIT.")
        raise self.STATE_INIT()

    # RECEIVE CONDITIONS
    ####################

    @ATMT.receive_condition(SELECTING)
    def receive_offer(self, pkt):
        """Receive offer on SELECTING state."""
        logger.debug("C2. Received OFFER?, in SELECTING state.")
        if isoffer(pkt):
            logger.debug("C2: T, OFFER received")
            self.offers.append(pkt)
            if len(self.offers) >= MAX_OFFERS_COLLECTED:
                logger.debug("C2.5: T, raise REQUESTING.")
                self.select_offer()
                raise self.REQUESTING()
            logger.debug("C2.5: F, raise SELECTING.")
            raise self.SELECTING()

    # same as:, but would can not be overloaded
    # @ATMT.receive_condition(RENEWING)
    # @ATMT.receive_condition(REBINDING)
    @ATMT.receive_condition(REQUESTING)
    def receive_ack_requesting(self, pkt):
        """Receive ACK in REQUESTING state."""
        logger.debug("C3. Received ACK?, in REQUESTING state.")
        if self.process_received_ack(pkt):
            logger.debug("C3: T. Received ACK, in REQUESTING state, "
                         "raise BOUND.")
            raise self.BOUND()

    # same as:, but would can not be overloaded
    # @ATMT.receive_condition(RENEWING)
    # @ATMT.receive_condition(REBINDING)
    @ATMT.receive_condition(REQUESTING)
    def receive_nak_requesting(self, pkt):
        """Receive NAK in REQUESTING state."""
        logger.debug("C3.1. Received NAK?, in REQUESTING state.")
        if self.process_received_nak(pkt):
            logger.debug("C3.1: T. Received NAK, in REQUESTING state, "
                         "raise INIT.")
            raise self.INIT()

    @ATMT.receive_condition(RENEWING)
    def receive_ack_renewing(self, pkt):
        """Receive ACK in RENEWING state."""
        logger.debug("C3. Received ACK?, in RENEWING state.")
        if self.process_received_ack(pkt):
            logger.debug("C3: T. Received ACK, in RENEWING state, "
                         "raise BOUND.")
            raise self.BOUND()

    @ATMT.receive_condition(RENEWING)
    def receive_nak_renewing(self, pkt):
        """Receive NAK in RENEWING state."""
        logger.debug("C3.1. Received NAK?, in RENEWING state.")
        if self.process_received_nak(pkt):
            logger.debug("C3.1: T. Received NAK, in RENEWING state, "
                         " raise INIT.")
            raise self.INIT()

    @ATMT.receive_condition(REBINDING)
    def receive_ack_rebinding(self, pkt):
        """Receive ACK in REBINDING state."""
        logger.debug("C3. Received ACK?, in REBINDING state.")
        if self.process_received_ack(pkt):
            logger.debug("C3: T. Received ACK, in REBINDING state, "
                         "raise BOUND.")
            raise self.BOUND()

    @ATMT.receive_condition(REBINDING)
    def receive_nak_rebinding(self, pkt):
        """Receive NAK in REBINDING state."""
        logger.debug("C3.1. Received NAK?, in RENEWING state.")
        if self.process_received_nak(pkt):
            logger.debug("C3.1: T. Received NAK, in RENEWING state, "
                         "raise INIT.")
            raise self.INIT()

    # ACTIONS
    ##########

    # ACTIONS: on timeouts
    # -----------------------

    @ATMT.action(timeout_delay_before_selecting)
    @ATMT.action(timeout_selecting)
    def action_transmit_discover(self):
        """Action on timeout, send DISCOVER."""
        logger.debug('Action on timeout, in state %s: send DISCOVER.',
                     self.current_state)
        self.send_discover()

    @ATMT.action(timeout_requesting)
    @ATMT.action(timeout_request_rebinding)
    @ATMT.action(rebinding_time_expires)
    @ATMT.action(receive_offer)
    @ATMT.action(timeout_request_renewing)
    @ATMT.action(renewing_time_expires)
    def action_transmit_request(self):
        """Action on X: send REQUEST."""
        logger.debug('Action on timeout X/receive X, in state %s: '
                     'send REQUEST.', self.current_state)
        self.send_request()

    # ACTIONS: on receive conditions
    # -------------------------------

    @ATMT.action(receive_ack_rebinding)
    @ATMT.action(receive_ack_requesting)
    def on_ack_requesting(self):
        """Action on receive ACK requesting in REQUESTING state: set timers."""
        # NOTE: not recording lease
        logger.debug('Action on receive ACK in REQUESTING state: set timers.')
        self.set_timers()

    @ATMT.action(receive_ack_renewing)
    def on_renewing(self):
        """Action on renewing on RENEWING state.

        Not recording lease, but restarting timers.

        """
        self.client.lease.sanitize_net_values()
        self.client.lease.set_times(self.time_sent_request)
        self.set_timers()
