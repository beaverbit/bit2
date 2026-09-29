# interface de linha de comando
# argumentos, orquestracao e print final

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import __version__
from .colors import B, CYN, DIM, GRN, MAG, RED, YEL, c, col, color_enabled
from .colors import CLR_LINE
from .scanner import scan_port
from .signatures import TOP_PORTS
from .targets import (
    discover_hosts,
    parse_port_list,
    parse_ports,
    parse_targets,
    reverse,
)


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


def print_progress(done, total, start, prefixo="scan", width=30):
    # barra de progresso simples, sem frescura
    pct = done / total if total else 0
    cheio = int(width * pct)
    barra = "#" * cheio + "-" * (width - cheio)
    dt = time.time() - start
    eta = (dt / done * (total - done)) if done else 0
    msg = (
        CLR_LINE
        + c(f"[{prefixo}] ", DIM)
        + c("[", DIM) + c(barra, CYN) + c("]", DIM)
        + f" {done}/{total}  "
        + c(f"{pct*100:5.1f}%", B)
        + f"  {dt:5.1f}s  "
        + c(f"eta {eta:4.1f}s", DIM)
    )
    sys.stderr.write(msg)
    sys.stderr.flush()


def clear_progress():
    # apaga a linha inteira usando ANSI, sem contar espaco
    sys.stderr.write(CLR_LINE)
    sys.stderr.flush()


def scan_single_target(host, ip, ports, args):
    # roda um scan completo em um host
    rdns = reverse(ip) if ip != host else None
    print_header(host, ip, rdns, len(ports), args.threads, args.timeout)

    t0 = time.time()
    results = []
    total = len(ports)
    done = 0
    show_progress = (
        not args.live
        and not args.no_progress
        and sys.stderr.isatty()
        and color_enabled()
        and total > 1
    )

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_port, host, ip, p, args.timeout, args.service): p for p in ports}
        try:
            for fut in as_completed(futs):
                r = fut.result()
                results.append(r)
                done += 1
                if args.live:
                    if r["state"] == "open":
                        print_result(r)
                    elif args.verbose and not args.open_only:
                        print_result(r)
                elif show_progress:
                    print_progress(done, total, t0)
        except KeyboardInterrupt:
            if show_progress:
                clear_progress()
            raise

    if show_progress:
        clear_progress()

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

    return {
        "host": host,
        "ip": ip,
        "rdns": rdns,
        "scanned": len(ports),
        "duration": round(dt, 3),
        "results": sorted(results, key=lambda x: x["port"]),
    }


def build_parser():
    ap = argparse.ArgumentParser(
        prog="bit2",
        description="bit2 - scanner de porta, sem enrolacao",
        epilog="ex: bit2 -p 1-1024 -t 200 --top 192.168.0.0/24",
    )
    ap.add_argument("host", help="alvo: host, CIDR (10.0.0.0/24), range (10.0.0.1-10.0.0.20) ou lista com virgula")
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
    ap.add_argument("--skip-discovery", action="store_true", help="pula host discovery, escaneia direto")
    ap.add_argument(
        "--discovery-ports",
        metavar="SPEC",
        help="portas do discovery (default: 80,443,22,8080,3389,445)",
    )
    ap.add_argument("--version", action="version", version=f"bit2 {__version__}")
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)

    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    # decide quais portas
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print(c("erro: spec de porta invalida", RED), file=sys.stderr)
            sys.exit(1)
    else:
        ports = TOP_PORTS

    if not ports:
        print(c("erro: nenhuma porta pra escanear", RED), file=sys.stderr)
        sys.exit(1)

    # portas do discovery
    discovery_ports = None
    if args.discovery_ports:
        try:
            discovery_ports = parse_port_list(args.discovery_ports)
        except ValueError:
            print(c("erro: --discovery-ports invalido", RED), file=sys.stderr)
            sys.exit(1)

    # resolve alvos (pode ser 1 ou varios)
    targets = parse_targets(args.host)
    if not targets:
        print(c(f"erro: nenhum alvo valido em '{args.host}'", RED), file=sys.stderr)
        sys.exit(1)

    multi = len(targets) > 1
    total_alvos_originais = len(targets)

    if multi:
        print(c(f"[*] {total_alvos_originais} alvos na fila", DIM), file=sys.stderr)

    # warn se threads for absurdo
    if args.threads > 1000:
        print(
            c(f"[!] -t {args.threads} pode estourar o limite de file descriptors do SO, considere 200-500", YEL),
            file=sys.stderr,
        )

    # discovery so faz sentido com varios alvos
    if multi and not args.skip_discovery:
        targets = discover_hosts(targets, max(args.timeout, 1.0), min(args.threads, 256), discovery_ports)
        if not targets:
            print(c("nenhum host vivo, saindo", YEL), file=sys.stderr)
            sys.exit(0)
    elif multi and args.skip_discovery:
        print(c("[*] discovery pulado, escaneando todos os alvos", DIM), file=sys.stderr)

    filtrados = total_alvos_originais - len(targets)

    all_reports = []
    t_global = time.time()

    try:
        for idx, (label, ip) in enumerate(targets, 1):
            if multi:
                print()
                print(c(f"===== [{idx}/{len(targets)}] {label} =====", B + MAG))
            report = scan_single_target(label, ip, ports, args)
            all_reports.append(report)
    except KeyboardInterrupt:
        print(c("\n[!] abortado", YEL), file=sys.stderr)
        sys.exit(130)

    dt_global = time.time() - t_global

    # resumo final se rolou mais de um alvo
    if multi:
        print()
        print(c("=" * 52, DIM))
        print(c("resumo geral", B + CYN))
        print(c("=" * 52, DIM))
        total_opens = 0
        for r in all_reports:
            n = sum(1 for x in r["results"] if x["state"] == "open")
            total_opens += n
            if n > 0:
                tag = c(" up ", GRN)
            else:
                # host respondeu mas nao achou porta aberta: fica neutro
                tag = c(" ?  ", DIM)
            print(f" [{tag}] {r['ip']:<16} {c(str(n) + ' abertas', B)}")
        print(c("-" * 52, DIM))
        # linha de hosts com contexto de discovery
        if filtrados > 0:
            info_hosts = f"{len(all_reports)} vivos de {total_alvos_originais} alvos ({filtrados} filtrado(s) no discovery)"
        elif args.skip_discovery:
            info_hosts = f"{len(all_reports)} alvos (discovery pulado)"
        else:
            info_hosts = f"{len(all_reports)} alvos"
        print(f"{c('hosts:', B)} {info_hosts}")
        print(f"{c('portas abertas:', B)} {c(str(total_opens), GRN)}  {c(f'({dt_global:.2f}s)', DIM)}")

    if args.json_out:
        payload = {
            "targets": len(all_reports),
            "duration": round(dt_global, 3),
            "reports": all_reports,
        }
        # se for 1 alvo so, mantem formato antigo pra nao quebrar pipeline
        if len(all_reports) == 1:
            payload = all_reports[0]
        with open(args.json_out, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"{c('json salvo em:', B)} {args.json_out}")


if __name__ == "__main__":
    main()
