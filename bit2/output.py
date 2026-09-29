# formatadores de saida
# normal (bonito), xml (nmap-like) e grep (pipeline)
# xml e grep SO mostram portas relevantes (open / open|filtered)
# closed e filtered ficam de fora, é o que nmap faz por padrao

import time
import xml.sax.saxutils as sax

from . import __version__


# estados que interessam pra output maquina (aberta ou "nao sei")
RELEVANT_STATES = ("open", "open|filtered")


def is_open(r):
    # so conta como aberta de verdade, sem sombra de duvida
    # open|filtered NAO conta, é indeterminado
    return r.get("state") == "open"


def fmt_normal_header(host, ip, rdns, ports_count, threads, timeout, proto):
    # monta o bloco de cabecalho como string (o print rola no cli)
    linhas = []
    linhas.append("")
    linhas.append(f"bit2 scan report for {host}")
    linhas.append("-" * 52)
    if ip and ip != host:
        linhas.append(f"IP:       {ip}")
    if rdns:
        linhas.append(f"rDNS:     {rdns}")
    linhas.append(f"Portas:   {ports_count}")
    linhas.append(f"Proto:    {proto}")
    linhas.append(f"Threads:  {threads}")
    linhas.append(f"Timeout:  {timeout}s")
    linhas.append("-" * 52)
    return linhas


def _relevant(results):
    # filtra so o que importa pra output maquina
    return [r for r in results if r["state"] in RELEVANT_STATES]


def fmt_xml(reports):
    # gera XML estilo nmap (simplificado mas parseavel por ferramentas)
    # reports pode ser 1 dict ou lista
    if isinstance(reports, dict):
        reports = [reports]
    ts = int(time.time())
    out = []
    out.append('<?xml version="1.0" encoding="UTF-8"?>')
    out.append('<!DOCTYPE nmaprun>')
    out.append(f'<nmaprun scanner="bit2" version="{__version__}" start="{ts}" args="bit2">')
    for rep in reports:
        host_attr = sax.quoteattr(rep["ip"])
        out.append('  <host>')
        out.append('    <status state="up"/>')
        out.append(f'    <address addr={host_attr} addrtype="ipv4"/>')
        if rep.get("rdns"):
            out.append(f'    <hostnames><hostname name={sax.quoteattr(rep["rdns"])}/></hostnames>')
        out.append('    <ports>')
        for r in _relevant(rep["results"]):
            state = r["state"]
            if state == "open|filtered":
                state_xml = "open|filtered"
                reason = "no-response"
            elif state == "open":
                state_xml = "open"
                reason = "syn-ack" if r.get("proto") == "tcp" else "udp-response"
            else:
                state_xml = "filtered"
                reason = "no-response"
            proto = r.get("proto", "tcp")
            out.append(f'      <port protocol="{proto}" portid="{r["port"]}">')
            out.append(f'        <state state="{state_xml}" reason="{reason}"/>')
            if r.get("service"):
                svc_name = sax.quoteattr(r["service"].lower())
                ver = sax.quoteattr(r.get("banner") or "")
                out.append(f'        <service name={svc_name} version={ver}/>')
            out.append('      </port>')
        out.append('    </ports>')
        out.append('  </host>')
    out.append('</nmaprun>')
    return "\n".join(out)


def fmt_grep(reports):
    # formato host:porta:proto:estado:servico:banner
    # so portas relevantes, facil de dar grep/awk depois
    if isinstance(reports, dict):
        reports = [reports]
    linhas = []
    for rep in reports:
        ip = rep["ip"]
        for r in _relevant(rep["results"]):
            proto = r.get("proto", "tcp")
            svc = r.get("service") or ""
            banner = (r.get("banner") or "").replace(":", " ").replace("\n", " ")
            linhas.append(f"{ip}:{r['port']}:{proto}:{r['state']}:{svc}:{banner}".rstrip(":"))
    return "\n".join(linhas)
