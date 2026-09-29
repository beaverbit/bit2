# parsing de alvos e portas
# resolve dns, cidr, range, lista

import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from .colors import CLR_LINE, DIM, GRN, YEL, c, color_enabled
from .scanner import probe_host
from .signatures import DISCOVERY_PORTS


def resolve(host):
    # resolve host pra ip, aceita ip direto tbm
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def reverse(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def parse_targets(spec):
    # aceita: host unico, CIDR, range de ip, lista com virgula
    # devolve lista de (host_label, ip) pra escanear
    targets = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        # tenta CIDR primeiro (tem barra)
        if "/" in chunk:
            try:
                net = ipaddress.ip_network(chunk, strict=False)
                for ip in net.hosts():
                    targets.append((str(ip), str(ip)))
                continue
            except ValueError:
                pass
        # tenta range tipo 10.0.0.1-10.0.0.20
        if "-" in chunk and chunk.count(".") >= 3:
            try:
                a, b = chunk.split("-", 1)
                start = ipaddress.ip_address(a.strip())
                # b pode ser ip completo ou so o ultimo octeto
                if "." in b:
                    end = ipaddress.ip_address(b.strip())
                else:
                    base = str(start).rsplit(".", 1)[0]
                    end = ipaddress.ip_address(f"{base}.{b.strip()}")
                cur = int(start)
                fim = int(end)
                if cur > fim:
                    cur, fim = fim, cur
                for n in range(cur, fim + 1):
                    ip = str(ipaddress.ip_address(n))
                    targets.append((ip, ip))
                continue
            except ValueError:
                pass
        # senao trata como host unico (dominio ou ip)
        ip = resolve(chunk)
        if ip:
            targets.append((chunk, ip))
        else:
            print(c(f"aviso: nao resolveu {chunk}, pulando", YEL), file=sys.stderr)
    return targets


def parse_ports(spec):
    # aceita "80", "80,443", "1-1024", "22,80,8000-8100"
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p < 65536)


def parse_port_list(spec):
    # wrapper do parse_ports pra usar como lista de discovery
    return parse_ports(spec)


def discover_hosts(targets, timeout, threads, ports=None):
    # filtra os hosts que respondem, paralelo
    if not targets:
        return []
    probe_ports = ports or DISCOVERY_PORTS
    vivos = []
    total = len(targets)
    done = 0
    print(c(f"[*] host discovery: {total} alvos, batendo em {probe_ports}", DIM), file=sys.stderr)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(probe_host, ip, probe_ports, timeout): (label, ip) for label, ip in targets}
        for fut in as_completed(futs):
            label, ip = futs[fut]
            done += 1
            try:
                if fut.result():
                    vivos.append((label, ip))
            except Exception:
                pass
            if sys.stderr.isatty() and color_enabled():
                sys.stderr.write(f"{CLR_LINE}{c('[disc]', DIM)} {done}/{total}")
                sys.stderr.flush()
    if sys.stderr.isatty() and color_enabled():
        sys.stderr.write(CLR_LINE)
        sys.stderr.flush()
    print(c(f"[+] {len(vivos)}/{total} hosts vivos", GRN if vivos else YEL), file=sys.stderr)
    return vivos
