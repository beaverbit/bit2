#!/usr/bin/env python3
# bit2 - scanner de porta maroto
# feito na tora, sem frescura

import argparse
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# cores, porque terminal sem cor é triste
R = "\033[0m"
B = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GRN = "\033[32m"
YEL = "\033[33m"
BLU = "\033[34m"
MAG = "\033[35m"
CYN = "\033[36m"

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


def color_enabled():
    # se nao for tty, melhor nao sujar
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def c(txt, cor):
    if not color_enabled():
        return txt
    return f"{cor}{txt}{R}"


def col(txt, width, cor=None):
    # alinha primeiro, colore depois
    # assim a cor nunca conta como caractere
    base = str(txt)
    espacos = " " * max(0, width - len(base))
    if cor and color_enabled():
        return f"{cor}{base}{R}{espacos}"
    return base + espacos


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


def grab_banner(sock, host, port, timeout):
    # tenta arrancar banner do servico
    try:
        payload = PROBES.get(port)
        if payload:
            if b"%s" in payload:
                payload = payload % host.encode()
            sock.sendall(payload)
        sock.settimeout(timeout)
        data = sock.recv(1024)
        return data
    except Exception:
        return b""


def identify(banner):
    # tenta adivinhar o servico pelo banner
    if not banner:
        return None, None
    for name, rx in SIGS:
        m = rx.search(banner)
        if m:
            extra = m.group(0).decode("latin-1", "ignore").strip()
            return name, extra[:60]
    return None, None


def scan_port(host, ip, port, timeout, service_detect):
    # o coracao do negocio, uma porta por thread
    result = {"port": port, "state": "closed", "service": None, "banner": None}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        r = s.connect_ex((ip, port))
        if r == 0:
            result["state"] = "open"
            if service_detect:
                banner = grab_banner(s, host, port, timeout)
                if banner:
                    name, extra = identify(banner)
                    result["service"] = name
                    result["banner"] = extra or banner[:80].decode("latin-1", "ignore").strip()
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return result


def print_header(host, ip, rdns, ports_count, threads, timeout):
    print()
    print(c(f"bit2 scan report for {host}", B + CYN))
    print(c("-" * 52, DIM))
    if ip and ip != host:
        print(f"{c('IP:', B)}       {ip}")
    if rdns:
        print(f"{c('rDNS:', B)}     {rdns}")
    print(f"{c('Portas:', B)}   {ports_count}")
    print(f"{c('Threads:', B)}  {threads}")
    print(f"{c('Timeout:', B)}  {timeout}s")
    print(c("-" * 52, DIM))
    # cabecalho alinhado na mao, sem f-string malandra
    linha = (
        col("PORT", 20, B)
        + col("STATE", 12, B)
        + col("SERVICE", 12, B)
        + col("VERSION", 0, B)
    )
    print(linha)


def print_result(r):
    port = f"{r['port']}/tcp"
    if r["state"] == "open":
        cor_state = GRN
    elif r["state"] == "closed":
        cor_state = RED
    else:
        cor_state = YEL

    svc_txt = r.get("service") or ""
    ver = r.get("banner") or ""
    if len(ver) > 60:
        ver = ver[:57] + "..."

    linha = (
        col(port, 20)
        + col(r["state"], 12, cor_state)
        + col(svc_txt, 12)
        + ver
    )
    print(linha)


def print_progress(done, total, start, width=30):
    # barra de progresso simples, sem frescura
    pct = done / total if total else 0
    cheio = int(width * pct)
    barra = "#" * cheio + "-" * (width - cheio)
    dt = time.time() - start
    eta = (dt / done * (total - done)) if done else 0
    msg = f"\r{c('[', DIM)}{c(barra, CYN)}{c(']', DIM)} {done}/{total}  {c(f'{pct*100:5.1f}%', B)}  {c(f'{dt:5.1f}s', DIM)}  {c(f'eta {eta:4.1f}s', DIM)}"
    sys.stderr.write(msg)
    sys.stderr.flush()


def clear_progress():
    # limpa a linha da barra
    sys.stderr.write("\r" + " " * 90 + "\r")
    sys.stderr.flush()


def main():
    ap = argparse.ArgumentParser(
        prog="bit2",
        description="bit2 - scanner de porta, sem enrolacao",
        epilog="ex: bit2 -p 1-1024 -t 200 --top 192.168.0.1",
    )
    ap.add_argument("host", help="alvo (ip ou dominio)")
    ap.add_argument("-p", "--ports", help="portas: 80 | 80,443 | 1-1024 | 22,80,8000-8100")
    ap.add_argument("--top", action="store_true", help="escaneia as top 100 portas")
    ap.add_argument("-t", "--threads", type=int, default=100, help="threads (default 100)")
    ap.add_argument("-T", "--timeout", type=float, default=1.5, help="timeout em segundos (default 1.5)")
    ap.add_argument("-sV", "--service", action="store_true", help="detecta servico/banner")
    ap.add_argument("--json", dest="json_out", metavar="FILE", help="salva resultado em json")
    ap.add_argument("-v", "--verbose", action="store_true", help="mostra porta fechada tbm")
    ap.add_argument("--no-color", action="store_true", help="sem cor")
    ap.add_argument("--open-only", action="store_true", help="mostra so porta aberta")
    ap.add_argument("--live", action="store_true", help="imprime em tempo real (sem ordenar)")
    ap.add_argument("--no-progress", action="store_true", help="sem barra de progresso")
    args = ap.parse_args()

    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    # decide quais portas
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print(c("erro: spec de porta invalida", RED), file=sys.stderr)
            sys.exit(1)
    elif args.top:
        ports = TOP_PORTS
    else:
        ports = TOP_PORTS

    if not ports:
        print(c("erro: nenhuma porta pra escanear", RED), file=sys.stderr)
        sys.exit(1)

    host = args.host
    ip = resolve(host)
    if not ip:
        print(c(f"erro: nao resolveu {host}", RED), file=sys.stderr)
        sys.exit(1)

    rdns = reverse(ip) if ip != host else None

    print_header(host, ip, rdns, len(ports), args.threads, args.timeout)

    t0 = time.time()
    results = []
    total = len(ports)
    done = 0
    # barra so aparece se nao for --live, se tiver tty e nao for --no-progress
    show_progress = (
        not args.live
        and not args.no_progress
        and sys.stderr.isatty()
        and color_enabled()
    )

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_port, host, ip, p, args.timeout, args.service): p for p in ports}
        try:
            for fut in as_completed(futs):
                r = fut.result()
                results.append(r)
                done += 1
                if args.live:
                    # modo tempo real, imprime na hora
                    if r["state"] == "open":
                        print_result(r)
                    elif args.verbose and not args.open_only:
                        print_result(r)
                elif show_progress:
                    print_progress(done, total, t0)
        except KeyboardInterrupt:
            if show_progress:
                clear_progress()
            print(c("\n[!] abortado", YEL), file=sys.stderr)
            for f in futs:
                f.cancel()
            sys.exit(130)

    if show_progress:
        clear_progress()

    # modo default: ordena e imprime tudo no final
    if not args.live:
        results.sort(key=lambda x: x["port"])
        for r in results:
            if r["state"] == "open":
                print_result(r)
            elif args.verbose and not args.open_only:
                print_result(r)

    opens = [r for r in results if r["state"] == "open"]
    dt = time.time() - t0

    print(c("-" * 52, DIM))
    print(f"{c('abertas:', B)} {c(str(len(opens)), GRN)}/{len(ports)}  {c(f'({dt:.2f}s)', DIM)}")

    if args.json_out:
        # ordena sempre no json, mesmo em --live
        ordered = sorted(results, key=lambda x: x["port"])
        payload = {
            "host": host,
            "ip": ip,
            "rdns": rdns,
            "scanned": len(ports),
            "duration": round(dt, 3),
            "results": ordered,
        }
        with open(args.json_out, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"{c('json salvo em:', B)} {args.json_out}")


if __name__ == "__main__":
    main()
