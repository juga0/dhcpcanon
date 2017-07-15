# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
"""."""
import logging
import logging.config
from datetime import datetime

from scapy.automaton import Automaton
from scapy.config import conf

from dhcpcanon.conflog import LOGGING
from dhcpcanon.constants import STATES2NAMES
from dhcpcanon.dhcpcapfsm import DHCPCAPFSM
from dhcpcap_pkts import dhcp_ack, dhcp_offer
from dhcpcapfsm_objs import (fsm_bound, fsm_init, fsm_preinit, fsm_requesting,
                             fsm_selecting)

logging.config.dictConfig(LOGGING)
logger = logging.getLogger('dhcpcanon')
logger_scapy_interactive = logging.getLogger('scapy.interactive')
logger.setLevel(logging.DEBUG)
logger_scapy_interactive.setLevel(logging.DEBUG)


class DummySocket(object):
    def __init__(self, *args, **kargs):
        pass

    def send(self, pkt):
        pass

    def fileno(self):
        return 0

    def recv(self, n=0):
        return dhcp_offer

    def close(self):
        pass


class DummySocketAck(DummySocket):
    def recv(self, n=0):
        return dhcp_ack


class TestDHCPCAPFSM:
    """."""

    def test_round_trip(self):
        logger.debug('Test PREINIT')
        fsm_preinit['script'].script_init(fsm_preinit['client'].lease,
                                          fsm_preinit['current_state'])
        # recvsock=DummySocket) will fail with python3
        conf.L2listen = DummySocket
        # for sendp:
        conf.L2socket = DummySocket
        dhcpcanon = DHCPCAPFSM(client_mac='00:01:02:03:04:05', iface='eth0',
                               scriptfile='/sbin/dhclient-script',
                               delay_selecting=1, timeout_select=1,
                               ll=DummySocket)
        assert dhcpcanon.dict_self() == fsm_preinit
        logger.debug('Test INIT')
        logger.debug('============')
        logger.debug('state %s', STATES2NAMES[dhcpcanon.current_state])
        fsm_init['script'].script_init(fsm_init['client'].lease,
                                       fsm_init['current_state'] - 1)
        logger.debug('Test start running, INIT')
        try:
            dhcpcanon.next()
        except Automaton.Singlestep as err:
            logger.debug('Singlestep %s in state %s', err,
                         dhcpcanon.current_state)
        assert dhcpcanon.dict_self() == fsm_init
        logger.debug('Test SELECTING')
        logger.debug('===============')
        logger.debug('State %s', STATES2NAMES[dhcpcanon.current_state])
        logger.debug('Num offers %s', len(dhcpcanon.offers))
        fsm_selecting['script'].script_init(fsm_init['client'].lease,
                                            'PREINIT')
        logger.debug('Test timeout selecting %s',
                     dhcpcanon.get_timeout(dhcpcanon.current_state,
                                           dhcpcanon.timeout_selecting))
        # FIXME:110 why is needed here to press enter to don't retransmit?
        try:
            dhcpcanon.next()
        except Automaton.Singlestep as err:
            logger.debug('Singlestep %s in state %s', err,
                         dhcpcanon.current_state)
        # os.kill(os.getpid(), signal.SIGCONT)
        # logger.debug(dhcpcanon.dict_self()['script'])
        # logger.debug(fsm_selecting['script'])
        # TODO: case when offer is not received,
        # and next step is selecting again
        if len(dhcpcanon.offers) < 1:
            logger.debug('Offer not received, tests are not complete yet.')
            return
        assert dhcpcanon.dict_self()['script'] == fsm_selecting['script']
        assert dhcpcanon.dict_self()['client'].lease == \
            fsm_selecting['client'].lease
        assert dhcpcanon.dict_self()['client'] == \
            fsm_selecting['client']
        # with mock.patch('dhcpcanon.timers.nowutc',
        #                 return_value=datetime(2017, 6, 23)):
        dhcpcanon.time_sent_request = datetime(2017, 6, 23)
        assert dhcpcanon.dict_self() == fsm_selecting
        logger.debug('Test REQUESTING')
        logger.debug('=================')
        logger.debug('State %s', STATES2NAMES[dhcpcanon.current_state])
        # dummy socket that will receive an ACK
        dhcpcanon.listen_sock = DummySocketAck()
        fsm_requesting['script'].script_init(fsm_init['client'].lease,
                                             'PREINIT')
        try:
            dhcpcanon.next()
        except Automaton.Singlestep as err:
            logger.debug('Singlestep %s in state %s', err,
                         dhcpcanon.current_state)

        assert dhcpcanon.dict_self()['script'] == fsm_requesting['script']
        # set the timers accourding to the time pkt sent
        # dhcpcanon.client.lease.set_times(datetime(2017, 6, 23))
        dhcpcanon.set_timers()
        assert dhcpcanon.dict_self()['client'].lease == \
            fsm_requesting['client'].lease
        assert dhcpcanon.dict_self()['client'] == \
            fsm_requesting['client']
        assert dhcpcanon.dict_self() == fsm_requesting
        logger.debug('Test BOUND')
        logger.debug('============')
        logger.debug('State %s', STATES2NAMES[dhcpcanon.current_state])
        fsm_bound['script'].script_init(fsm_bound['client'].lease,
                                        'BOUND')
        try:
            dhcpcanon.next()
        except Automaton.Singlestep as err:
            logger.debug('Singlestep %s in state %s', err,
                         dhcpcanon.current_state)
        assert dhcpcanon.dict_self()['script'] == fsm_bound['script']
        assert dhcpcanon.dict_self()['client'].lease == \
            fsm_bound['client'].lease
        assert dhcpcanon.dict_self()['client'] == \
            fsm_bound['client']
        assert dhcpcanon.dict_self() == fsm_bound
        # os.kill(os.getpid(), signal.SIGINT)
