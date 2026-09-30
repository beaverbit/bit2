# testes de parsing de alvos e portas
# sem rede real, so logica pura

import pytest

from bit2.targets import parse_ports, parse_targets


class TestParsePorts:
    def test_porta_unica(self):
        assert parse_ports("80") == [80]

    def test_lista_simples(self):
        assert parse_ports("80,443") == [80, 443]

    def test_range(self):
        assert parse_ports("1-5") == [1, 2, 3, 4, 5]

    def test_range_invertido(self):
        assert parse_ports("5-1") == [1, 2, 3, 4, 5]

    def test_misturado(self):
        assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]

    def test_deduplica(self):
        assert parse_ports("80,80,80") == [80]

    def test_ordena(self):
        assert parse_ports("443,80,22") == [22, 80, 443]

    def test_ignora_porta_invalida(self):
        assert parse_ports("0,80,70000") == [80]

    def test_string_vazia(self):
        assert parse_ports("") == []

    def test_input_invalido(self):
        with pytest.raises(ValueError):
            parse_ports("abc")

    def test_input_misto_invalido(self):
        with pytest.raises(ValueError):
            parse_ports("80,abc,443")


class TestParseTargets:
    def test_cidr_30(self):
        result = parse_targets("192.168.0.0/30")
        ips = [ip for _, ip in result]
        assert ips == ["192.168.0.1", "192.168.0.2"]

    def test_cidr_slash32(self):
        result = parse_targets("10.0.0.1/32")
        assert len(result) == 1

    def test_range_ip_completo(self):
        result = parse_targets("10.0.0.1-10.0.0.3")
        ips = [ip for _, ip in result]
        assert ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_range_ultimo_octeto(self):
        result = parse_targets("10.0.0.10-12")
        ips = [ip for _, ip in result]
        assert ips == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]

    def test_lista_com_virgula(self):
        result = parse_targets("10.0.0.1,10.0.0.2,10.0.0.3")
        assert len(result) == 3

    def test_host_unico_ip(self):
        result = parse_targets("127.0.0.1")
        assert len(result) == 1
        assert result[0][1] == "127.0.0.1"

    def test_string_vazia(self):
        assert parse_targets("") == []

    def test_cidr_invalido_ignorado(self):
        result = parse_targets("999.999.999.999/33")
        assert result == []
