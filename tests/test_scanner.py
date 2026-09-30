# testes do motor TCP
# mocka socket pra nao tocar rede de verdade

import socket
from unittest.mock import MagicMock, patch

from bit2.scanner import identify, scan_port


class TestIdentify:
    def test_ssh(self):
        name, extra = identify(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu")
        assert name == "SSH"
        assert "SSH-2.0-OpenSSH" in extra

    def test_http(self):
        name, extra = identify(b"HTTP/1.1 200 OK\r\nServer: nginx")
        assert name == "HTTP"
        assert "HTTP/1.1 200" in extra

    def test_ftp(self):
        name, _ = identify(b"220 ProFTPD Server ready")
        assert name == "FTP"

    def test_smtp(self):
        name, _ = identify(b"220 mail.example.com ESMTP Postfix")
        assert name == "SMTP"

    def test_redis(self):
        name, _ = identify(b"-ERR unknown command")
        assert name == "Redis"

    def test_vazio(self):
        name, extra = identify(b"")
        assert name is None
        assert extra is None

    def test_lixo(self):
        name, extra = identify(b"\x00\x01\x02\x03")
        assert name is None


class TestScanPort:
    @patch("bit2.scanner.socket.socket")
    def test_porta_aberta_sem_service(self, mock_socket):
        instance = MagicMock()
        instance.connect_ex.return_value = 0
        mock_socket.return_value = instance

        r = scan_port("localhost", "127.0.0.1", 22, 0.5, service_detect=False)

        assert r["port"] == 22
        assert r["state"] == "open"
        assert r["proto"] == "tcp"
        assert r["service"] is None

    @patch("bit2.scanner.socket.socket")
    def test_porta_fechada(self, mock_socket):
        instance = MagicMock()
        instance.connect_ex.return_value = 111
        mock_socket.return_value = instance

        r = scan_port("localhost", "127.0.0.1", 9999, 0.5, service_detect=False)

        assert r["state"] == "closed"

    @patch("bit2.scanner.grab_banner")
    @patch("bit2.scanner.socket.socket")
    def test_service_detect_com_banner(self, mock_socket, mock_grab):
        instance = MagicMock()
        instance.connect_ex.return_value = 0
        mock_socket.return_value = instance
        mock_grab.return_value = b"SSH-2.0-OpenSSH_9.0"

        r = scan_port("localhost", "127.0.0.1", 22, 0.5, service_detect=True)

        assert r["state"] == "open"
        assert r["service"] == "SSH"

    @patch("bit2.scanner.socket.socket")
    def test_socket_error_trata(self, mock_socket):
        instance = MagicMock()
        instance.connect_ex.side_effect = socket.error("boom")
        mock_socket.return_value = instance

        r = scan_port("localhost", "127.0.0.1", 22, 0.5, service_detect=False)

        assert r["state"] == "closed"
