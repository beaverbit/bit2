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
from .signatures import TOP_PORTS, UDP_TOP_PORTS
from .targets import (
    discover_hosts,
    parse_port_list,
    parse_ports,
    parse_targets,
    reverse,
)
from .udp import scan_udp_port
from . import output as out_fmt


def print_header(host, ip, rdns, ports_count, threads, timeout, proto="tcp"):
    linhas = out_fmt.fmt_normal_header(host, ip, rdns, ports_count, threads, timeout, proto)
    for i, linha in enumerate(linhas):
        if i == 1:
            print(c(linha, B + CYN))
        elif linha.startswith("-"):
            print(c(linha, DIM))
        elif linha.startswith(("IP:", "rDNS:", "Portas:", "Proto:", "Threads:", "Timeout:")):
            chave, _, valor = linha.partition(":")
            print(f"{c(chave + ':', B)} {valor.strip()}")
        else:
            print(linha)
    linha = (
        col("PORT", 20, B)
        + col("STATE", 14, B)
        + col("SERVICE", 12, B)
        + col("VERSION", 0, B)
    )
    print(linha)


def print_result(r):
    proto = r.get("proto", "tcp")
    port = f"{r['port']}/{proto}"
    state = r["state"]
    if state == "open":
        cor_state = GRN
    elif state == "closed":
        cor_state = RED
    elif state == "open|filtered":
        cor_state = YEL
    else:
        cor_state = YEL

    svc_txt = r.get("service") or ""
    ver = r.get("banner") or ""
    if len(ver) > 60:
        ver = ver[:57] + "..."

    linha = (
        col(port, 20)
        + col(state, 14, cor_state)
        + col(svc_txt, 12)
        + ver
    )
    print(linha)


def print_progress(done, total, start, prefixo="scan", width=30):
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
    sys.stderr.write(CLR_LINE)
    sys.stderr.flush()


def _dispatch(job):
    # job = (proto, host, ip, port, timeout, service)
    proto, host, ip, port, timeout, service = job
    if proto == "udp":
        return scan_udp_port(ip, port, timeout, service)
    return scan_port(host, ip, port, timeout, service)


def _split_counts(results):
    # conta abertas de verdade, indeterminadas (open|filtered) e fechadas
    n_open = sum(1 for r in results if r["state"] == "open")
    n_unkn = sum(1 for r in results if r["state"] == "open|filtered")
    n_closed = sum(1 for r in results if r["state"] == "closed")
    return n_open, n_unkn, n_closed


def scan_single_target(host, ip, jobs, args, proto_label, human_output):
    # human_output = True -> mostra header/tabela/resumo
    #                False -> modo xml/grep, so coleta os dados
    rdns = reverse(ip) if ip != host else None

    if human_output:
        print_header(host, ip, rdns, len(jobs), args.threads, args.timeout, proto_label)

    t0 = time.time()
    results = []
    total = len(jobs)
    done = 0
    show_progress = (
        human_output
        and not args.live
        and not args.no_progress
        and sys.stderr.isatty()
        and color_enabled()
        and total > 1
    )

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(_dispatch, j): j for j in jobs}
        try:
            for fut in as_completed(futs):
                r = fut.result()
                results.append(r)
                done += 1
                if human_output and args.live:
                    if r["state"] in out_fmt.RELEVANT_STATES:
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

    if human_output and not args.live:
        results.sort(key=lambda x: (x.get("proto", "tcp"), x["port"]))
        for r in results:
            if r["state"] in out_fmt.RELEVANT_STATES:
                print_result(r)
            elif args.verbose and not args.open_only:
                print_result(r)

    n_open, n_unkn, n_closed = _split_counts(results)
    dt = time.time() - t0

    if human_output:
        print(c("-" * 52, DIM))
        # linha de contagem sempre mostra abertas de verdade
        linha = f"{c('abertas:', B)} {c(str(n_open), GRN)}/{len(jobs)}"
        if n_unkn > 0:
            linha += f"  {c(str(n_unkn) + ' indeterminadas', YEL)}"
        if args.verbose:
            linha += f"  {c(str(n_closed) + ' fechadas', RED)}"
        linha += f"  {c(f'({dt:.2f}s)', DIM)}"
        print(linha)

    return {
        "host": host,
        "ip": ip,
        "rdns": rdns,
        "scanned": len(jobs),
        "proto": proto_label,
        "duration": round(dt, 3),
        "open": n_open,
        "open_filtered": n_unkn,
        "closed": n_closed,
        "results": sorted(results, key=lambda x: (x.get("proto", "tcp"), x["port"])),
    }


def build_parser():
    ap = argparse.ArgumentParser(
        prog="bit2",
        description="bit2 - scanner de porta, sem enrolacao",
        epilog="ex: bit2 -p 1-1024 -t 200 --top 192.168.0.0/24",
    )
    ap.add_argument("host", nargs="?", help="alvo: host, CIDR, range, lista com virgula")
    ap.add_argument("--target-file", metavar="FILE", help="arquivo com alvos (um por linha)")
    ap.add_argument("-p", "--ports", help="portas: 80 | 80,443 | 1-1024 | 22,80,8000-8100")
    ap.add_argument("--port-file", metavar="FILE", help="arquivo com portas (uma por linha ou spec)")
    ap.add_argument("--top", action="store_true", help="escaneia as top 100 portas TCP")
    ap.add_argument("--top-udp", action="store_true", help="escaneia as top UDP")
    ap.add_argument("-sU", "--udp", action="store_true", help="habilita scan UDP (so UDP)")
    ap.add_argument("--also-tcp", action="store_true", help="com -sU, escaneia TCP tambem")
    ap.add_argument("-t", "--threads", type=int, default=100, help="threads (default 100)")
    ap.add_argument("-T", "--timeout", type=float, default=1.5, help="timeout em segundos (default 1.5)")
    ap.add_argument("-sV", "--service", action="store_true", help="detecta servico/banner")
    ap.add_argument("--json", dest="json_out", metavar="FILE", help="salva resultado em json")
    ap.add_argument("--output", choices=["normal", "xml", "grep"], default="normal", help="formato de saida (default normal)")
    ap.add_argument("-v", "--verbose", action="store_true", help="mostra porta fechada tbm (so no modo normal)")
    ap.add_argument("--no-color", action="store_true", help="sem cor")
    ap.add_argument("--open-only", action="store_true", help="mostra so porta aberta")
    ap.add_argument("--live", action="store_true", help="imprime em tempo real (sem ordenar)")
    ap.add_argument("--no-progress", action="store_true", help="sem barra de progresso")
    ap.add_argument("--skip-discovery", action="store_true", help="pula host discovery")
    ap.add_argument("--discovery-ports", metavar="SPEC", help="portas do discovery")
    ap.add_argument("--version", action="version", version=f"bit2 {__version__}")
    return ap


def _load_lines(path):
    try:
        with open(path, "r") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except FileNotFoundError:
        print(c(f"erro: arquivo nao encontrado: {path}", RED), file=sys.stderr)
        sys.exit(1)


def _resolve_port_source(args):
    # prioridade: --port-file > -p > (None, deixa o caller decidir top)
    if args.port_file:
        linhas = _load_lines(args.port_file)
        if not linhas:
            print(c(f"erro: --port-file {args.port_file} vazio", RED), file=sys.stderr)
            sys.exit(1)
        spec = ",".join(linhas)
        try:
            return parse_ports(spec)
        except ValueError as e:
            print(c(f"erro: --port-file {args.port_file} tem conteudo invalido: {e}", RED), file=sys.stderr)
            print(c("dica: use um item por linha (ex: 80) ou range (ex: 1-1024)", DIM), file=sys.stderr)
            sys.exit(1)
    if args.ports:
        try:
            return parse_ports(args.ports)
        except ValueError:
            print(c("erro: spec de porta invalida", RED), file=sys.stderr)
            sys.exit(1)
    return None


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)

    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    human_output = args.output == "normal"

    # ---- resolve portas TCP e UDP ----
    explicito = _resolve_port_source(args)
    tcp_ports = []
    udp_ports = []

    if args.udp:
        if explicito is not None:
            udp_ports = explicito
        else:
            udp_ports = UDP_TOP_PORTS
        if args.also_tcp:
            tcp_ports = TOP_PORTS
    else:
        tcp_ports = explicito if explicito is not None else TOP_PORTS

    if not tcp_ports and not udp_ports:
        print(c("erro: nenhuma porta pra escanear", RED), file=sys.stderr)
        sys.exit(1)

    # ---- resolve alvos ----
    raw = args.host
    if args.target_file:
        linhas = _load_lines(args.target_file)
        raw = ",".join(linhas) if linhas else ""
    if not raw:
        print(c("erro: nenhum alvo passado (host ou --target-file)", RED), file=sys.stderr)
        sys.exit(1)

    targets = parse_targets(raw)
    if not targets:
        print(c(f"erro: nenhum alvo valido em '{raw}'", RED), file=sys.stderr)
        sys.exit(1)

    multi = len(targets) > 1
    total_alvos_originais = len(targets)

    if multi and human_output:
        print(c(f"[*] {total_alvos_originais} alvos na fila", DIM), file=sys.stderr)

    if args.threads > 1000:
        print(
            c(f"[!] -t {args.threads} pode estourar o limite de file descriptors do SO, considere 200-500", YEL),
            file=sys.stderr,
        )

    # discovery
    discovery_ports = None
    if args.discovery_ports:
        try:
            discovery_ports = parse_port_list(args.discovery_ports)
        except ValueError:
            print(c("erro: --discovery-ports invalido", RED), file=sys.stderr)
            sys.exit(1)

    if multi and not args.skip_discovery:
        targets = discover_hosts(targets, max(args.timeout, 1.0), min(args.threads, 256), discovery_ports)
        if not targets:
            if human_output:
                print(c("nenhum host vivo, saindo", YEL), file=sys.stderr)
            sys.exit(0)
    elif multi and args.skip_discovery and human_output:
        print(c("[*] discovery pulado, escaneando todos os alvos", DIM), file=sys.stderr)

    filtrados = total_alvos_originais - len(targets)

    # ---- monta jobs por host ----
    def jobs_for(host, ip):
        jobs = []
        for p in tcp_ports:
            jobs.append(("tcp", host, ip, p, args.timeout, args.service))
        for p in udp_ports:
            jobs.append(("udp", host, ip, p, args.timeout, args.service))
        return jobs

    proto_label = "tcp+udp" if (tcp_ports and udp_ports) else ("udp" if udp_ports else "tcp")

    all_reports = []
    t_global = time.time()

    try:
        for idx, (label, ip) in enumerate(targets, 1):
            if multi and human_output:
                print()
                print(c(f"===== [{idx}/{len(targets)}] {label} =====", B + MAG))
            report = scan_single_target(label, ip, jobs_for(label, ip), args, proto_label, human_output)
            all_reports.append(report)
    except KeyboardInterrupt:
        print(c("\n[!] abortado", YEL), file=sys.stderr)
        sys.exit(130)

    dt_global = time.time() - t_global

    # ---- resumo final (so no modo normal) ----
    if multi and human_output:
        print()
        print(c("=" * 52, DIM))
        print(c("resumo geral", B + CYN))
        print(c("=" * 52, DIM))
        total_open = 0
        total_unkn = 0
        for r in all_reports:
            n = r.get("open", 0)
            u = r.get("open_filtered", 0)
            total_open += n
            total_unkn += u
            # tag so fica "up" se achou porta aberta de verdade
            if n > 0:
                tag = c(" up ", GRN)
            elif u > 0:
                tag = c(" ~  ", YEL)
            else:
                tag = c(" ?  ", DIM)
            linha = f" [{tag}] {r['ip']:<16} {c(str(n) + ' abertas', B)}"
            if u > 0:
                linha += f"  {c(str(u) + ' indeterminadas', YEL)}"
            print(linha)
        print(c("-" * 52, DIM))
        if filtrados > 0:
            info_hosts = f"{len(all_reports)} vivos de {total_alvos_originais} alvos ({filtrados} filtrado(s) no discovery)"
        elif args.skip_discovery:
            info_hosts = f"{len(all_reports)} alvos (discovery pulado)"
        else:
            info_hosts = f"{len(all_reports)} alvos"
        print(f"{c('hosts:', B)} {info_hosts}")
        linha_final = f"{c('portas abertas:', B)} {c(str(total_open), GRN)}"
        if total_unkn > 0:
            linha_final += f"  {c(str(total_unkn) + ' indeterminadas', YEL)}"
        linha_final += f"  {c(f'({dt_global:.2f}s)', DIM)}"
        print(linha_final)

    # ---- output alternativo (vai limpo no stdout) ----
    if args.output == "xml":
        print(out_fmt.fmt_xml(all_reports))
    elif args.output == "grep":
        print(out_fmt.fmt_grep(all_reports))

    # ---- json (sempre em arquivo, aviso no stderr) ----
    if args.json_out:
        payload = {
            "targets": len(all_reports),
            "duration": round(dt_global, 3),
            "reports": all_reports,
        }
        if len(all_reports) == 1:
            payload = all_reports[0]
        with open(args.json_out, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"{c('json salvo em:', B)} {args.json_out}", file=sys.stderr)


if __name__ == "__main__":
    main()
