"""Controller regressions using real OS-Ken messages and a fake datapath."""
import logging
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser
import controller


class Datapath:
    ofproto = ofp
    ofproto_parser = parser

    def __init__(self, identifier=1):
        self.id = identifier
        self.messages = []
        self.xid = 0

    def set_xid(self, msg):
        self.xid += 1
        msg.xid = self.xid

    def send_msg(self, msg):
        self.messages.append(msg)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.app = controller.AuthAccessController.__new__(controller.AuthAccessController)
        self.app.logger = logging.getLogger("controller-test")
        self.dp = Datapath()
        self.app.datapaths = {1: self.dp}
        self.app.pending_operations = {}
        self.app._finish_operation = Mock(return_value="OK")

    def test_allow_match_priority_lease(self):
        self.assertEqual(self.app.process_command("ALLOW 10.0.0.1 10.0.0.4 8080 60"), "OK")
        msg = self.dp.messages[0]
        self.assertEqual(msg.priority, 200)
        self.assertEqual(msg.hard_timeout, 60)
        self.assertEqual(dict(msg.match.items()), dict(eth_type=2048, ip_proto=6,
                         ipv4_src="10.0.0.1", ipv4_dst="10.0.0.4", tcp_dst=8080))

    def test_revoke_strict_and_owned(self):
        self.assertEqual(self.app.apply_revoke("10.0.0.1", "10.0.0.4", 8080), "OK")
        msg = self.dp.messages[0]
        self.assertEqual(msg.command, ofp.OFPFC_DELETE_STRICT)
        self.assertEqual(msg.priority, 200)
        self.assertNotEqual(msg.cookie_mask, 0, "Deletion must be scoped to this app")

    def test_failed_allow_rolls_back(self):
        self.app._finish_operation.side_effect = ["ERR confirmation timed out", "OK"]
        self.assertTrue(self.app.apply_allow("10.0.0.1", "10.0.0.4", 8080, 60).startswith("ERR"))
        self.assertTrue(any(m.command == ofp.OFPFC_DELETE_STRICT for m in self.dp.messages))

    def test_revoke_attempts_other_switch_after_failure(self):
        second = Datapath(2)
        self.app.datapaths[2] = second
        self.app._finish_operation.side_effect = ["ERR disconnected", "OK"]
        self.assertTrue(self.app.apply_revoke("10.0.0.1", "10.0.0.4", 8080).startswith("ERR"))
        self.assertTrue(second.messages)

    def test_no_switch_and_bad_commands_rejected(self):
        for cmd in ["ALLOW ::1 10.0.0.4 8080 60", "ALLOW 10.0.0.1 10.0.0.5 8080 60",
                    "ALLOW 10.0.0.1 10.0.0.4 9000 60", "ALLOW 10.0.0.1 10.0.0.4 8080 0",
                    "ALLOW a b x y", "REVOKE", ""]:
            self.assertTrue(self.app.process_command(cmd).startswith("ERR"))
        self.app.datapaths.clear()
        self.assertEqual(self.app.apply_allow("10.0.0.1", "10.0.0.4", 8080, 60), "ERR no switch connected")

    def test_only_matching_barrier_wakes_operation(self):
        op = self.app._begin_operation(self.dp)
        op["event"] = Mock()
        op["barrier_xid"] = 17
        for xid in [16, 17]:
            self.app.barrier_reply_handler(SimpleNamespace(msg=SimpleNamespace(datapath=self.dp,xid=xid)))
        self.assertEqual(op["event"].set.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
