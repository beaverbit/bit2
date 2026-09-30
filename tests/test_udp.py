# testes do motor UDP
# mocka socket pra simular open / closed / open|filtered

import socket
from unittest.mock import MagicMock, patch

from bit2.udp import scan_udp_port


class TestScanUdpPort:
    @patch("bit2.udp.socket.socket")
    def test_resposta_vira_open(self, mock_socket):
        instance = MagicMock()
        instance.recv.return_value = b"hello-udp"
        mock_socket.return_value = instance

        r = scan_udp_port("127.0.0.1", 5353, 0.5, service_detect=False)

        assert r["port"] == 5353
        assert r["proto"] == "udp"
        assert r["state"] == "open"
        assert r["banner"] == "hello-udp"

    @patch("bit2.udp.socket.socket")
    def test_timeout_vira_open_filtered(self, mock_socket):
        instance = MagicMock()
        instance.recv.side_effect = socket.timeout()
        mock_socket.return_value = instance

        r = scan_udp_port("127.0.0.1", 123, 0.5, service_detect=False)

        assert r["state"] == "open|filtered"

    @patch("bit2.udp.socket.socket")
    def test_connection_refused_vira_closed(self, mock_socket):
        instance = MagicMock()
        instance.recv.side_effect = ConnectionRefusedError()
        mock_socket.return_value = instance

        r = scan_udp_port("127.0.0.1", 9999, 0.5, service_detect=False)

        assert r["state"] == "closed"

    @patch("bit2.udp.socket.socket")
    def test_oserror_errno_111_vira_closed(self, mock_socket):
        instance = MagicMock()
        err = OSError("connection refused")
        err.errno = 111
        instance.recv.side_effect = err
        mock_socket.return_value = instance

        r = scan_udp_port("127.0.0.1", 9999, 0.5, service_detect=False)

        assert r["state"] == "closed"

    @patch("bit2.udp.socket.socket")
    def test_connect_chamado(self, mock_socket):
        instance = MagicMock()
        instance.recv.side_effect = socket.timeout()
        mock_socket.return_value = instance

        scan_udp_port("127.0.0.1", 53, 0.5, service_detect=False)

        instance.connect.assert_called_once_with(("127.0.0.1", 53))
