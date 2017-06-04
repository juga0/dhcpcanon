# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
""""""
import logging
from dhcpcanon.constants import STATE_REQUESTING

FORMAT = "%(levelname)s: %(filename)s:%(lineno)s - %(funcName)s - " + \
         "%(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)

logger = logging.getLogger(__name__)


class TestDHCPCAPFSM:
    """."""
    def test_intialize(self, dhcpcanon):
        """."""
        assert dhcpcanon.client.client_mac == "00:0a:0b:0c:0d:0f"

    def test_set_timeout(self, dhcpcanon):
        """."""
        dhcpcanon.set_timeout(STATE_REQUESTING,
                              dhcpcanon.timeout_requesting, 1)
        timeout = dhcpcanon.get_timeout(STATE_REQUESTING,
                                        dhcpcanon.timeout_requesting)
        logger.debug('timeout %s', timeout)
        # FIXME
        # assert timeout == 1
