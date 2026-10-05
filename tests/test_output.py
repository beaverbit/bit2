# testes dos formatadores
# xml valido, grep formatado, is_open

import xml.etree.ElementTree as ET

from bit2.output import fmt_grep, fmt_xml, is_open


def _fake_report():
    return {
        "host": "scanme.nmap.org",
        "ip": "45.33.32.156",
        "rdns": "scanme.nmap.org",
        "scanned": 3,
        "proto": "tcp",
        "duration": 1.5,
        "results": [
            {"port": 22, "proto": "tcp", "state": "open", "service": "SSH", "banner": "SSH-2.0-OpenSSH_8.9", "confidence": 1.00},
            {"port": 80, "proto": "tcp", "state": "open", "service": "HTTP", "banner": "HTTP/1.1 200", "confidence": 0.98},
            {"port": 9999, "proto": "tcp", "state": "closed", "service": None, "banner": None, "confidence": 0.0},
        ],
    }


class TestIsOpen:
    def test_open_verdadeiro(self):
        assert is_open({"state": "open"}) is True

    def test_open_filtered_falso(self):
        assert is_open({"state": "open|filtered"}) is False

    def test_closed_falso(self):
        assert is_open({"state": "closed"}) is False

    def test_filtered_falso(self):
        assert is_open({"state": "filtered"}) is False


class TestFmtXml:
    def test_xml_valido(self):
        out = fmt_xml(_fake_report())
        root = ET.fromstring(out)
        assert root.tag == "nmaprun"

    def test_xml_tem_host(self):
        out = fmt_xml(_fake_report())
        root = ET.fromstring(out)
        host = root.find("host")
        assert host is not None
        addr = host.find("address")
        assert addr.get("addr") == "45.33.32.156"

    def test_xml_so_portas_relevantes(self):
        out = fmt_xml(_fake_report())
        root = ET.fromstring(out)
        ports = root.findall(".//port")
        assert len(ports) == 2
        portids = [p.get("portid") for p in ports]
        assert "22" in portids
        assert "80" in portids
        assert "9999" not in portids

    def test_xml_tem_service_com_confidence(self):
        out = fmt_xml(_fake_report())
        root = ET.fromstring(out)
        services = root.findall(".//service")
        names = [s.get("name") for s in services]
        assert "ssh" in names
        assert "http" in names
        # confidence tem que estar no ssh
        ssh = [s for s in services if s.get("name") == "ssh"][0]
        assert ssh.get("conf") == "1.00"

    def test_xml_lista_de_reports(self):
        out = fmt_xml([_fake_report(), _fake_report()])
        root = ET.fromstring(out)
        hosts = root.findall("host")
        assert len(hosts) == 2

    def test_xml_dict_unico(self):
        out = fmt_xml(_fake_report())
        root = ET.fromstring(out)
        hosts = root.findall("host")
        assert len(hosts) == 1


class TestFmtGrep:
    def test_grep_so_relevantes(self):
        out = fmt_grep(_fake_report())
        linhas = out.strip().split("\n")
        assert len(linhas) == 2
        assert "9999" not in out

    def test_grep_formato_com_confidence(self):
        out = fmt_grep(_fake_report())
        # formato: ip:porta:proto:state:service:confidence:banner
        assert "45.33.32.156:22:tcp:open:SSH:1.00:SSH-2.0-OpenSSH_8.9" in out

    def test_grep_remove_dois_pontos_do_banner(self):
        rep = _fake_report()
        rep["results"][0]["banner"] = "banner:com:dois:pontos"
        out = fmt_grep(rep)
        linha = [l for l in out.split("\n") if ":22:" in l][0]
        partes = linha.split(":")
        assert len(partes) >= 6

    def test_grep_dict_unico(self):
        out = fmt_grep(_fake_report())
        assert "45.33.32.156" in out
