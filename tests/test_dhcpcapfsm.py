""""""
import pytest
import logging
from dhcpcanon.dhcpcapfsm import DHCPCAPFSM
from dhcpcanon.constants import STATE_REQUESTING

FORMAT = "%(levelname)s: %(filename)s:%(lineno)s - %(funcName)s - " + \
         "%(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)



class TestDHCPCAPFSM:
    def test_intialize(self, dhcpcanon):
        assert dhcpcanon.client.client_mac == "00:0a:0b:0c:0d:0f"

    def test_set_timeout(self, dhcpcanon):
        dhcpcanon.set_timeout(STATE_REQUESTING, dhcpcanon.timeout_requesting, 1)
        timeout = dhcpcanon.get_timeout(STATE_REQUESTING,
                                        dhcpcanon.timeout_requesting)
        logger.debug('timeout %s', timeout)
        assert timeout == 1
