""""""
import pytest
import logging
from dhcpcanon.dhcpcapfsm import DHCPCAPFSM

FORMAT = "%(levelname)s: %(filename)s:%(lineno)s - %(funcName)s - " + \
         "%(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)



class TestDHCPCAPFSM:
    def test_intialize(self, dhcpcanon):
        assert dhcpcanon.client.client_mac == "00:0a:0b:0c:0d:0f"

# class TestDHCPCAPFSM(unittest.TestCase):
#     def TestBOUND(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.BOUND())
#         assert False # TODO: implement your test here
#
#     def TestEND(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.END())
#         assert False # TODO: implement your test here
#
#     def TestERROR(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.ERROR())
#         assert False # TODO: implement your test here
#
#     def TestINIT(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.INIT())
#         assert False # TODO: implement your test here
#
#     def TestREBINDING(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.REBINDING())
#         assert False # TODO: implement your test here
#
#     def TestRENEWING(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.RENEWING())
#         assert False # TODO: implement your test here
#
#     def TestREQUESTING(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.REQUESTING())
#         assert False # TODO: implement your test here
#
#     def TestSELECTING(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.SELECTING())
#         assert False # TODO: implement your test here
#
#     def test_get_timeout(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.get_timeout(state, function))
#         assert False # TODO: implement your test here
#
#     def test_lease_expires(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.lease_expires())
#         assert False # TODO: implement your test here
#
#     def test_on_ack_requesting(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.on_ack_requesting())
#         assert False # TODO: implement your test here
#
#     def test_on_rebinding(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.on_rebinding())
#         assert False # TODO: implement your test here
#
#     def test_on_rebinding_time_expires(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.on_rebinding_time_expires())
#         assert False # TODO: implement your test here
#
#     def test_on_renewing(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.on_renewing())
#         assert False # TODO: implement your test here
#
#     def test_on_renewing_time_expires(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.on_renewing_time_expires())
#         assert False # TODO: implement your test here
#
#     def test_on_retransmit_discover(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.on_retransmit_discover())
#         assert False # TODO: implement your test here
#
#     def test_on_retransmit_request(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.on_retransmit_request())
#         assert False # TODO: implement your test here
#
#     def test_on_retransmit_request_rebinding(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.on_retransmit_request_rebinding())
#         assert False # TODO: implement your test here
#
#     def test_on_retransmit_request_renewing(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.on_retransmit_request_renewing())
#         assert False # TODO: implement your test here
#
#     def test_on_select_offer(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.on_select_offer())
#         assert False # TODO: implement your test here
#
#     def test_on_timeout_delay_selecting(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.on_timeout_delay_selecting())
#         assert False # TODO: implement your test here
#
#     def test_parse_args(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.parse_args(iface, server_port, client_port, client_mac, scriptfile))
#         assert False # TODO: implement your test here
#
#     def test_process_received_ack(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.process_received_ack(pkt))
#         assert False # TODO: implement your test here
#
#     def test_process_received_nak(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.process_received_nak(pkt))
#         assert False # TODO: implement your test here
#
#     def test_rebinding_time_expires(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.rebinding_time_expires())
#         assert False # TODO: implement your test here
#
#     def test_receive_ack_rebinding(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.receive_ack_rebinding(pkt))
#         assert False # TODO: implement your test here
#
#     def test_receive_ack_renewing(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.receive_ack_renewing(pkt))
#         assert False # TODO: implement your test here
#
#     def test_receive_ack_requesting(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.receive_ack_requesting(pkt))
#         assert False # TODO: implement your test here
#
#     def test_receive_nak_rebinding(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.receive_nak_rebinding(pkt))
#         assert False # TODO: implement your test here
#
#     def test_receive_nak_renewing(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.receive_nak_renewing(pkt))
#         assert False # TODO: implement your test here
#
#     def test_receive_nak_requesting(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.receive_nak_requesting(pkt))
#         assert False # TODO: implement your test here
#
#     def test_receive_offer(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.receive_offer(pkt))
#         assert False # TODO: implement your test here
#
#     def test_renewing_time_expires(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.renewing_time_expires())
#         assert False # TODO: implement your test here
#
#     def test_reset(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.reset(iface, client_mac, **kargs))
#         assert False # TODO: implement your test here
#
#     def test_select_offer(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.select_offer())
#         assert False # TODO: implement your test here
#
#     def test_send_discover(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.send_discover())
#         assert False # TODO: implement your test here
#
#     def test_send_request(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.send_request())
#         assert False # TODO: implement your test here
#
#     def test_set_timeout(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.set_timeout(state, function, newtimeout))
#         assert False # TODO: implement your test here
#
#     def test_set_timers(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.set_timers())
#         assert False # TODO: implement your test here
#
#     def test_timeout_delay_selecting(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.timeout_delay_selecting())
#         assert False # TODO: implement your test here
#
#     def test_timeout_request_rebinding(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.timeout_request_rebinding())
#         assert False # TODO: implement your test here
#
#     def test_timeout_request_renewing(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.timeout_request_renewing())
#         assert False # TODO: implement your test here
#
#     def test_timeout_requesting(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.timeout_requesting())
#         assert False # TODO: implement your test here
#
#     def test_timeout_selecting(self):
#         # d_hcpcapfs_m = DHCPCAPFSM()
#         # self.assertEqual(expected, d_hcpcapfs_m.timeout_selecting())
#         assert False # TODO: implement your test here
#
# if __name__ == '__main__':
#     unittest.main()
