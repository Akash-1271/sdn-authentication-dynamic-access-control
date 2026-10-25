
import json
import time
from control_security import load_secret, new_challenge, verify_request, MAX_ENVELOPE_BYTES
from net_protocol import receive_line, decode_json

import ipaddress
import os

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from os_ken.lib import hub
from os_ken.lib.hub import StreamServer
from os_ken.ofproto import ofproto_v1_3


CONTROL_HOST = os.environ.get("SDN_CONTROL_HOST", "10.0.0.254")
CONTROL_ALLOWED_PEER = os.environ.get("SDN_CONTROL_ALLOWED_PEER", "10.0.0.3")
CONTROL_MAX_CONNECTIONS = 32
CONTROL_MESSAGE_SECONDS = 5

CONTROL_PORT = int(os.environ.get("SDN_CONTROL_PORT", "9999"))

PROTECTED_SERVER_IP = os.environ.get(
    "PROTECTED_SERVER_IP", "10.0.0.4"
)
PROTECTED_SERVER_PORT = int(
    os.environ.get("PROTECTED_SERVER_PORT", "8080")
)

DENY_PRIORITY = 100
ALLOW_PRIORITY = 200
MAX_LEASE_SECONDS = 3600
MAX_COMMAND_BYTES = 1024
BARRIER_TIMEOUT_SECONDS = 3
ALLOW_COOKIE = 0x53444E4155544801
COOKIE_MASK = 0xFFFFFFFFFFFFFFFF


class AuthAccessController(app_manager.OSKenApp):
    """SDN controller for authentication-based network access."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.control_key = load_secret()
        if not self.valid_ipv4(CONTROL_HOST) or CONTROL_HOST == "0.0.0.0":
            raise ValueError("Bind the control listener to a specific IPv4 management address")
        if not self.valid_ipv4(CONTROL_ALLOWED_PEER):
            raise ValueError("Control peer must be one IPv4 address")
        self.control_slots = hub.Semaphore(CONTROL_MAX_CONNECTIONS)
        self.datapaths = {}
        self.pending_operations = {}

        # Serialize commands so barrier responses cannot be confused
        # between simultaneous ALLOW/REVOKE requests.
        self.command_lock = hub.Semaphore(1)

        self.control_server = StreamServer(
            (CONTROL_HOST, CONTROL_PORT),
            self.handle_control_client,
        )
        hub.spawn(self.control_server.serve_forever)

        self.logger.info(
            "Custom TCP control listener configured on %s:%s",
            CONTROL_HOST,
            CONTROL_PORT,
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        """Install initial forwarding and deny rules."""
        datapath = event.msg.datapath
        self.datapaths[datapath.id] = datapath

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Clear only this application's temporary grants after reconnection.
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, command=ofproto.OFPFC_DELETE,
            cookie=ALLOW_COOKIE, cookie_mask=COOKIE_MASK,
            table_id=0, out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY, match=parser.OFPMatch()))

        # Install the deny before enabling ordinary forwarding.
        self.add_flow(datapath, priority=DENY_PRIORITY,
                      match=self.protected_match(datapath))

        # Ordinary traffic uses normal OVS forwarding.
        self.add_flow(
            datapath,
            priority=0,
            match=parser.OFPMatch(),
            actions=[
                parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)
            ],
        )

        self.logger.info(
            "Switch %s connected; default protected-service deny installed",
            datapath.id,
        )

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER],
    )
    def switch_state_handler(self, event):
        datapath = event.datapath

        if event.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath

        elif event.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self.logger.warning(
                "Switch %s disconnected", datapath.id
            )

            operation = self.pending_operations.get(datapath.id)
            if operation is not None:
                operation["errors"].append("Switch disconnected")
                operation["event"].set()

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, event):
        """Wake the matching command after the switch replies to its barrier."""
        datapath = event.msg.datapath
        operation = self.pending_operations.get(datapath.id)

        if (
            operation is not None
            and event.msg.xid == operation.get("barrier_xid")
        ):
            operation["event"].set()

    @set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [CONFIG_DISPATCHER, MAIN_DISPATCHER],
    )
    def error_msg_handler(self, event):
        """Record errors for flow modifications in a pending operation."""
        datapath = event.msg.datapath
        operation = self.pending_operations.get(datapath.id)

        if (
            operation is not None
            and event.msg.xid in operation["flow_xids"]
        ):
            error_text = (
                f"type={event.msg.type}, code={event.msg.code}"
            )
            operation["errors"].append(error_text)

            self.logger.error(
                "Switch rejected flow modification: dpid=%s %s",
                datapath.id,
                error_text,
            )

    def _send_flow_message(self, datapath, message):
        """Track a FlowMod XID before sending it to the switch."""
        operation = self.pending_operations.get(datapath.id)

        if operation is not None:
            datapath.set_xid(message)
            operation["flow_xids"].add(message.xid)

        datapath.send_msg(message)

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions=None,
        hard_timeout=0,
        cookie=0,
    ):
        """Install a flow rule; no actions means drop matching packets."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instructions = []

        if actions is not None:
            instructions.append(
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions,
                )
            )

        message = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            hard_timeout=hard_timeout,
            cookie=cookie,
        )

        self._send_flow_message(datapath, message)

    def protected_match(self, datapath, client_ip=None):
        """Match IPv4 TCP traffic to the protected service."""
        fields = {
            "eth_type": 0x0800,
            "ip_proto": 6,
            "ipv4_dst": PROTECTED_SERVER_IP,
            "tcp_dst": PROTECTED_SERVER_PORT,
        }

        if client_ip is not None:
            fields["ipv4_src"] = client_ip

        return datapath.ofproto_parser.OFPMatch(**fields)

    def _begin_operation(self, datapath):
        operation = {
            "event": hub.Event(),
            "flow_xids": set(),
            "errors": [],
            "barrier_xid": None,
        }

        self.pending_operations[datapath.id] = operation
        return operation

    def _wait_for_switch(self, datapath, operation):
        """Wait for the barrier reply after preceding FlowMods."""
        parser = datapath.ofproto_parser
        barrier = parser.OFPBarrierRequest(datapath)

        # Assign the XID first so we only accept the correct barrier reply.
        datapath.set_xid(barrier)
        operation["barrier_xid"] = barrier.xid
        datapath.send_msg(barrier)

        timer = hub.Timeout(BARRIER_TIMEOUT_SECONDS)

        try:
            operation["event"].wait()

        except hub.Timeout:
            return "ERR switch confirmation timed out"

        finally:
            timer.cancel()

        if operation["errors"]:
            return "ERR switch rejected flow update"

        return "OK"

    def _finish_operation(self, datapath, operation):
        try:
            return self._wait_for_switch(datapath, operation)
        finally:
            if self.pending_operations.get(datapath.id) is operation:
                del self.pending_operations[datapath.id]

    @staticmethod
    def valid_ipv4(address):
        try:
            return ipaddress.ip_address(address).version == 4
        except ValueError:
            return False

    def apply_allow(self, client_ip, server_ip, port, lease):
        if not self.valid_ipv4(client_ip):
            return "ERR invalid client IP"

        if not self.valid_ipv4(server_ip):
            return "ERR invalid server IP"

        if server_ip != PROTECTED_SERVER_IP:
            return "ERR unexpected server IP"

        if port != PROTECTED_SERVER_PORT:
            return "ERR unexpected service port"

        if not 1 <= lease <= MAX_LEASE_SECONDS:
            return "ERR invalid lease"

        datapaths = list(self.datapaths.values())

        if not datapaths:
            return "ERR no switch connected"

        for datapath in datapaths:
            operation = self._begin_operation(datapath)

            try:
                actions = [
                    datapath.ofproto_parser.OFPActionOutput(
                        datapath.ofproto.OFPP_NORMAL, 0
                    )
                ]

                self.add_flow(
                    datapath,
                    priority=ALLOW_PRIORITY,
                    match=self.protected_match(datapath, client_ip),
                    actions=actions,
                    hard_timeout=lease,
                    cookie=ALLOW_COOKIE,
                )

                result = self._finish_operation(datapath, operation)

            except Exception:
                self.apply_revoke(client_ip, server_ip, port)
                raise
            finally:
                if self.pending_operations.get(datapath.id) is operation:
                    del self.pending_operations[datapath.id]

            if result != "OK":
                rollback = self.apply_revoke(client_ip, server_ip, port)
                if rollback != "OK":
                    self.logger.error("ALLOW rollback unconfirmed: %s", rollback)
                self.logger.error(
                    "ALLOW not confirmed: client=%s result=%s",
                    client_ip,
                    result,
                )
                return result

        self.logger.info(
            "ALLOW confirmed: client=%s service=%s:%s lease=%s",
            client_ip, server_ip, port, lease,
        )
        return "OK"

    def apply_revoke(self, client_ip, server_ip, port):
        if not self.valid_ipv4(client_ip):
            return "ERR invalid client IP"

        if not self.valid_ipv4(server_ip):
            return "ERR invalid server IP"

        if server_ip != PROTECTED_SERVER_IP:
            return "ERR unexpected server IP"

        if port != PROTECTED_SERVER_PORT:
            return "ERR unexpected service port"

        datapaths = list(self.datapaths.values())

        if not datapaths:
            return "ERR no switch connected"

        failures = []
        for datapath in datapaths:
            operation = self._begin_operation(datapath)

            try:
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto

                message = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE_STRICT,
                    cookie=ALLOW_COOKIE,
                    cookie_mask=COOKIE_MASK,
                    table_id=0,
                    priority=ALLOW_PRIORITY,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=self.protected_match(datapath, client_ip),
                )

                self._send_flow_message(datapath, message)
                result = self._finish_operation(datapath, operation)

            except Exception as exc:
                self.logger.error("REVOKE send failed: %s", exc)
                result = "ERR switch revocation failed"
            finally:
                if self.pending_operations.get(datapath.id) is operation:
                    del self.pending_operations[datapath.id]

            if result != "OK":
                self.logger.error(
                    "REVOKE not confirmed: client=%s result=%s",
                    client_ip,
                    result,
                )
                failures.append(result)

        if failures:
            return failures[0]

        self.logger.info(
            "REVOKE confirmed: client=%s service=%s:%s",
            client_ip, server_ip, port,
        )
        return "OK"

    def process_command(self, line):
        """Validate and execute one newline-delimited command."""
        fields = line.split()

        try:
            if len(fields) == 5 and fields[0] == "ALLOW":
                _, client_ip, server_ip, port_text, lease_text = fields

                return self.apply_allow(
                    client_ip,
                    server_ip,
                    int(port_text),
                    int(lease_text),
                )

            if len(fields) == 4 and fields[0] == "REVOKE":
                _, client_ip, server_ip, port_text = fields

                return self.apply_revoke(
                    client_ip,
                    server_ip,
                    int(port_text),
                )

        except ValueError:
            return "ERR invalid numeric field"

        return "ERR malformed command"

    def handle_control_client(self, conn, address):
        """One challenge-bound HMAC request per connection; no sensitive logging."""
        acquired = self.control_slots.acquire(blocking=False)
        with conn:
            conn.settimeout(0.1)
            try:
                if not acquired:
                    conn.sendall(b"ERR busy\n")
                    return
                if address[0] != CONTROL_ALLOWED_PEER:
                    conn.sendall(b"ERR unauthorized peer\n")
                    return
                deadline = time.monotonic() + CONTROL_MESSAGE_SECONDS
                challenge = new_challenge()
                conn.settimeout(CONTROL_MESSAGE_SECONDS)
                conn.sendall(json.dumps(challenge, separators=(",", ":")).encode() + b"\n")
                line = receive_line(conn, MAX_ENVELOPE_BYTES,
                                    CONTROL_MESSAGE_SECONDS, deadline=deadline)
                if line is None:
                    return
                try:
                    envelope = decode_json(line)
                    command = verify_request(envelope, challenge, self.control_key)
                except (ValueError, TypeError):
                    command = None
                if command is None:
                    conn.settimeout(1)
                    conn.sendall(b"ERR authentication failed\n")
                    return
                with self.command_lock:
                    response = self.process_command(command)
                conn.settimeout(1)
                conn.sendall(response.encode("utf-8") + b"\n")
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                self.logger.warning("Control connection rejected: reason=%s", type(exc).__name__)
            except Exception:
                self.logger.error("Internal control request failure")
            finally:
                if acquired:
                    self.control_slots.release()
