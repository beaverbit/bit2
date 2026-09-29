# motor de scan
# aqui mora o connect, o banner grab e a identificacao

import socket

from .signatures import PROBES, SIGS


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


def probe_host(ip, ports, timeout):
    # tenta descobrir se o host ta vivo batendo em algumas portas comuns
    # tcp connect, sem precisar de root
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                return True
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False
