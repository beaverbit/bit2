# testes do motor TCP

import errno
import socket
from unittest.mock import MagicMock, patch

from bit2.scanner import classify_tcp_error, identify, scan_port


class TestIdentify:
    def test_ssh(self):
        name, extra, conf = identify(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu")
        assert name == "SSH"
        assert "SSH-2.0-OpenSSH" in extra
        assert conf == 1.00

    def test_http(self):
        name, extra, conf = identify(b"HTTP/1.1 200 OK\r\nServer: nginx")
        assert name == "HTTP"
        assert "HTTP/1.1 200" in extra
        assert conf == 0.98

    def test_ftp(self):
        name, _, conf = identify(b"220 ProFTPD Server ready")
        assert name == "FTP"
        assert conf > 0

    def test_smtp(self):
        name, _, _ = identify(b"220 mail.example.com ESMTP Postfix")
        assert name == "SMTP"

    def test_redis_err(self):
        # só casa redis quando o banner é claro
        name, _, conf = identify(b"-ERR unknown command 'foo'")
        assert name == "Redis"
        assert conf >= 0.9

    def test_redis_noauth(self):
        name, _, _ = identify(b"-NOAUTH Authentication required")
        assert name == "Redis"

    def test_redis_falso_positivo_evitado(self):
        # antes "+OK" caia como redis, agora tem que cair como POP3 ou nada
        name, _, _ = identify(b"+OK POP3 ready")
        assert name == "POP3"

    def test_vazio(self):
        name, extra, conf = identify(b"")
        assert name is None
        assert extra is None
        assert conf == 0.0

    def test_lixo(self):
        name, extra, conf = identify(b"\x00\x01\x02\x03")
        assert name is None
        assert conf == 0.0


class TestClassifyTcpError:
    def test_econnrefused_vira_closed(self):
        assert classify_tcp_error(errno.ECONNREFUSED) == "closed"

    def test_etimedout_vira_filtered(self):
        assert classify_tcp_error(errno.ETIMEDOUT) == "filtered"

    def test_ehostunreach_vira_filtered(self):
        assert classify_tcp_error(errno.EHOSTUNREACH) == "filtered"

    def test_enetunreach_vira_filtered(self):
        assert classify_tcp_error(errno.ENETUNREACH) == "filtered"

    def test_eacces_vira_filtered(self):
        assert classify_tcp_error(errno.EACCES) == "filtered"

    def test_erro_desconhecido_vira_filtered(self):
        # 999 nao existe, cai no fallback
        assert classify_tcp_error(999) == "filtered"


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
        assert r["confidence"] == 0.0

    @patch("bit2.scanner.socket.socket")
    def test_porta_fechada(self, mock_socket):
        instance = MagicMock()
        instance.connect_ex.return_value = errno.ECONNREFUSED
        mock_socket.return_value = instance

        r = scan_port("localhost", "127.0.0.1", 9999, 0.5, service_detect=False)

        assert r["state"] == "closed"

    @patch("bit2.scanner.socket.socket")
    def test_porta_filtrada_por_erro(self, mock_socket):
        instance = MagicMock()
        instance.connect_ex.return_value = errno.ETIMEDOUT
        mock_socket.return_value = instance

        r = scan_port("localhost", "127.0.0.1", 9999, 0.5, service_detect=False)

        assert r["state"] == "filtered"

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
        assert r["confidence"] == 1.00

    @patch("bit2.scanner.socket.socket")
    def test_socket_error_generico_vira_filtered(self, mock_socket):
        instance = MagicMock()
        instance.connect_ex.side_effect = socket.error("boom")
        mock_socket.return_value = instance

        r = scan_port("localhost", "127.0.0.1", 22, 0.5, service_detect=False)

        # erro desconhecido eh tratado como filtered (nao arriscamos dizer closed)
        assert r["state"] == "filtered"

    @patch("bit2.scanner.socket.socket")
    def test_retry_em_filtered(self, mock_socket):
        # connect_ex sempre devolve timeout, deve tentar retries+1 vezes
        instance = MagicMock()
        instance.connect_ex.return_value = errno.ETIMEDOUT
        mock_socket.return_value = instance

        r = scan_port("localhost", "127.0.0.1", 9999, 0.5, service_detect=False, retries=2)

        assert r["state"] == "filtered"
        # 3 tentativas (retry=2 + 1 inicial)
        assert instance.connect_ex.call_count == 3

    @patch("bit2.scanner.socket.socket")
    def test_retry_em_closed_nao_repete(self, mock_socket):
        # porta fechada decide de primeira, nao precisa retry
        instance = MagicMock()
        instance.connect_ex.return_value = errno.ECONNREFUSED
        mock_socket.return_value = instance

        r = scan_port("localhost", "127.0.0.1", 9999, 0.5, service_detect=False, retries=5)

        assert r["state"] == "closed"
        assert instance.connect_ex.call_count == 1
