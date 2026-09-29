# assinaturas, portas e payloads
# tudo que e "banco de dados" da ferramenta fica aqui

import re

# portas que uso pra descobrir se host ta vivo (as mais comuns de responder)
DISCOVERY_PORTS = [80, 443, 22, 8080, 3389, 445]

# as porta mais manjada da net, baseado no top 100 do nmap
TOP_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
]

# portas UDP mais comuns (baseado no top do nmap)
UDP_TOP_PORTS = [
    7, 9, 17, 19, 49, 53, 67, 68, 69, 80, 88, 111, 120, 123, 135, 136, 137,
    138, 139, 158, 161, 162, 177, 389, 407, 427, 443, 445, 464, 500, 514, 515,
    517, 518, 520, 593, 623, 626, 631, 996, 997, 998, 999, 1000, 1022, 1023,
    1025, 1026, 1027, 1028, 1029, 1030, 1433, 1434, 1645, 1646, 1701, 1718,
    1719, 1812, 1813, 1900, 1971, 1972, 2049, 2222, 3283, 3389, 3703, 4500,
    5060, 5353, 5432, 5632, 5678, 5679, 7734, 8000, 8080, 9000, 9001, 9200,
    10000, 17185, 20031, 30718, 31337, 32768, 32769, 32771, 32815, 33281,
    49152, 49153, 49154, 49156, 49181, 49182, 49185, 49186, 49188, 49190,
    49191, 49192, 49193, 49194, 49195, 49196, 49198, 49201, 49202, 49204,
    49205, 49207, 49208, 49211, 49213, 49215, 49216, 49217, 49218, 49219,
    49220, 49221, 49222, 49223, 49224, 49225, 49226, 49227, 49228, 49229,
    49230, 49231, 49232, 49233, 49234, 49235, 49236, 49237, 49238, 49239,
    49240, 49241, 49242, 49243, 49244, 49245, 49246, 49247, 49248, 49249,
    49250, 49251, 49252, 49253, 49254, 49255, 49256, 49257, 49258, 49259,
    49260, 49261, 49262, 49263, 49264, 49265, 49266, 49267, 49268, 49269,
    49270, 49271, 49272, 49273, 49274, 49275, 49276, 49277, 49278, 49279,
    49280, 49281, 49282, 49283, 49284, 49285, 49286, 49287, 49288, 49289,
    49290, 49291, 49292, 49293, 49294, 49295, 49296, 49297, 49298, 49299,
    49300,
]

# assinatura de servico por banner, na base do regex
# ordem importa, primeiro que casar ganha
SIGS = [
    ("SSH", re.compile(rb"^SSH-([\d.]+)-([\w.]+)")),
    ("HTTP", re.compile(rb"^HTTP/[\d.]+ \d+")),
    ("FTP", re.compile(rb"^220[- ].*FTP", re.I)),
    ("SMTP", re.compile(rb"^220[- ].*(SMTP|ESMTP|Postfix|Exim|Sendmail)", re.I)),
    ("POP3", re.compile(rb"^\+OK")),
    ("IMAP", re.compile(rb"^\* OK")),
    ("MySQL", re.compile(rb"^.{3}\x00.{1}\x00")),
    ("Redis", re.compile(rb"^[-+#]")),
    ("MongoDB", re.compile(rb"^.{4}\x00\x00\x00")),
    ("VNC", re.compile(rb"^RFB \d{3}\.\d{3}")),
    ("Telnet", re.compile(rb"^[\r\n]*\xff[\xfb-\xfe]")),
    ("RDP", re.compile(rb"^\x03\x00\x00")),
    ("SMB", re.compile(rb"^\x00\x00\x00")),
    ("Memcached", re.compile(rb"^VERSION ")),
]

# payload pra cutucar alguns servicos e ver se responde (TCP)
PROBES = {
    80: b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    443: b"",  # https nao da pra falar cru, deixa quieto
}

# payloads UDP por porta conhecida
# se nao tiver, manda pacote vazio mesmo
UDP_PAYLOADS = {
    # DNS: query vazia pra root NS
    53: (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x02\x00\x01"
    ),
    # NTP: client request v3
    123: b"\x1b" + b"\x00" * 47,
    # SNMP v1 get-request pra sysDescr
    161: (
        b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
        b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
        b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x01\x05\x00"
    ),
    # SSDP M-SEARCH
    1900: (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    ),
    # mDNS query
    5353: (
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x05local\x00\x00\xff\x00\x01"
    ),
    # IKE (ISAKMP) - initiator
    500: b"\x00" * 28,
    # NetBIOS name service
    137: (
        b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    ),
}
