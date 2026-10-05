# motor de scan TCP
# UDP mora em udp.py, aqui so TCP + discovery
# classificacao alinha com nmap: open / closed / filtered

import errno
import socket

from .signatures import PROBES, SIGS


# codigos de erro que significam "porta fechada" (RST veio)
_CLOSED_ERRNOS = {
    errno.ECONNREFUSED,  # 111 no linux
}

# codigos de erro que significam "filtrado" (sem resposta, rota ruim, etc)
_FILTERED_ERRNOS = {
    errno.ETIMEDOUT,
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.EHOSTDOWN,
    errno.ENETDOWN,
    errno.EACCES,
    errno.EPERM,
}


def classify_tcp_error(err_code):
    # devolve o state ("closed" / "filtered") baseado no errno do connect_ex
    if err_code in _CLOSED_ERRNOS:
        return "closed"
    if err_code in _FILTERED_ERRNOS:
        return "filtered"
    # qualquer outro errno ou codigo desconhecido: filtered e a melhor aposta
    return "filtered"


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
    # devolve (nome, trecho, confidence) ou (None, None, 0.0)
    if not banner:
        return None, None, 0.0
    for name, rx, conf in SIGS:
        m = rx.search(banner)
        if m:
            extra = m.group(0).decode("latin-1", "ignore").strip()
            return name, extra[:60], conf
    return None, None, 0.0


def _try_connect(ip, port, timeout):
    # faz um connect_ex isolado, devolve (err_code, sock_ou_None)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((ip, port))
        return code, s
    except socket.timeout:
        # timeout nao tem err_code, tratamos separado
        try:
            s.close()
        except Exception:
            pass
        return None, None
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None, None


def scan_port(host, ip, port, timeout, service_detect, retries=0):
    # scan TCP de uma porta
    # retries: numero de tentativas extras antes de desistir (so faz sentido pra filtered)
    result = {
        "port": port,
        "proto": "tcp",
        "state": "filtered",
        "service": None,
        "banner": None,
        "confidence": 0.0,
    }

    tentativas = retries + 1
    sock_aberto = None
    state_final = "filtered"

    for i in range(tentativas):
        code, s = _try_connect(ip, port, timeout)
        if code == 0:
            sock_aberto = s
            state_final = "open"
            break
        if code is None:
            # timeout -> filtered
            state_final = "filtered"
        else:
            state_final = classify_tcp_error(code)
            # se for closed, nem retry, ja sabemos
            if state_final == "closed":
                break
        # se for filtered, tenta de novo (se tiver retry)
        if state_final != "filtered":
            break

    result["state"] = state_final

    if sock_aberto is not None:
        try:
            if service_detect:
                banner = grab_banner(sock_aberto, host, port, timeout)
                if banner:
                    name, extra, conf = identify(banner)
                    result["service"] = name
                    result["confidence"] = conf
                    result["banner"] = extra or banner[:80].decode("latin-1", "ignore").strip()
        finally:
            try:
                sock_aberto.close()
            except Exception:
                pass

    return result


def probe_host(ip, ports, timeout):
    # tenta descobrir se o host ta vivo batendo em algumas portas comuns
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
