# testes de integracao com servidor TCP/UDP local
# aqui a gente toca rede de verdade, mas so em localhost

import socket
import threading
import time

import pytest

from bit2.scanner import scan_port
from bit2.udp import scan_udp_port


# -------- helpers pra subir servidores efemeros --------

class TcpEchoServer:
    # sobe um servidor TCP local que aceita conexao e manda um banner
    # roda em thread separada, porta automatica (0)

    def __init__(self, banner=b"HELLO\n"):
        self.banner = banner
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self.sock.settimeout(0.2)
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(1.0)
                conn.sendall(self.banner)
                # le o que o cliente mandar (probe)
                try:
                    conn.recv(1024)
                except Exception:
                    pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


class UdpEchoServer:
    # sobe um servidor UDP local que responde qualquer pacote com um banner

    def __init__(self, response=b"UDPSRV\n"):
        self.response = response
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(1024)
                self.sock.sendto(self.response, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


# -------- testes --------

class TestTcpIntegration:
    def test_porta_aberta_de_verdade(self):
        srv = TcpEchoServer(banner=b"SSH-2.0-IntegrationTest\n")
        try:
            time.sleep(0.05)
            r = scan_port("127.0.0.1", "127.0.0.1", srv.port, 1.0, service_detect=True)
            assert r["state"] == "open"
            # banner veio como SSH
            assert r["service"] == "SSH"
        finally:
            srv.stop()

    def test_porta_fechada_de_verdade(self):
        # pega uma porta que ninguem ta escutando
        # abre e fecha pra ter certeza que ninguem ta la
        tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmp.bind(("127.0.0.1", 0))
        free_port = tmp.getsockname()[1]
        tmp.close()

        r = scan_port("127.0.0.1", "127.0.0.1", free_port, 0.5, service_detect=False)
        assert r["state"] == "closed"

    def test_timeout_curto_em_porta_aberta_ainda_conecta(self):
        srv = TcpEchoServer()
        try:
            time.sleep(0.05)
            r = scan_port("127.0.0.1", "127.0.0.1", srv.port, 0.5, service_detect=False)
            assert r["state"] == "open"
        finally:
            srv.stop()


class TestUdpIntegration:
    def test_udp_responde_vira_open(self):
        srv = UdpEchoServer(response=b"UDPOK\n")
        try:
            time.sleep(0.05)
            r = scan_udp_port("127.0.0.1", srv.port, 1.0, service_detect=False)
            assert r["state"] == "open"
            assert "UDPOK" in (r["banner"] or "")
        finally:
            srv.stop()

    def test_udp_porta_fechada_vira_closed(self):
        # porta UDP que ninguem escuta
        tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tmp.bind(("127.0.0.1", 0))
        free_port = tmp.getsockname()[1]
        tmp.close()

        r = scan_udp_port("127.0.0.1", free_port, 0.5, service_detect=False)
        # em localhost, o ICMP port unreachable chega -> closed
        assert r["state"] == "closed"
