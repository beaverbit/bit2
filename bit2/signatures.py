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

# payload pra cutucar alguns servicos e ver se responde
PROBES = {
    80: b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",
    443: b"",  # https nao da pra falar cru, deixa quieto
}
