# motor de scan UDP
# truque do connect: sem connect, o kernel engole o ICMP port-unreachable
# e a gente nunca ve a porta como closed. com connect, ele entrega
# como ECONNREFUSED no proximo recvfrom

import socket

from .signatures import UDP_PAYLOADS


def _payload_for(port):
    # devolve payload conhecido ou vazio
    return UDP_PAYLOADS.get(port, b"")


def _one_probe(ip, port, timeout, payload):
    # faz um probe isolado, devolve state
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, port))
        s.settimeout(timeout)
        # se nao tem payload conhecido, manda 1 byte pra provocar ICMP
        # port-unreachable em porta fechada (senao fica open|filtered)
        data_to_send = payload if payload else b"\x00"
        try:
            s.send(data_to_send)
        except Exception:
            pass
        try:
            data = s.recv(2048)
            return "open", data
        except socket.timeout:
            return "open|filtered", b""
        except ConnectionRefusedError:
            return "closed", b""
        except OSError as e:
            if getattr(e, "errno", None) == 111:
                return "closed", b""
            return "open|filtered", b""
    except Exception:
        return "open|filtered", b""
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan_udp_port(ip, port, timeout, service_detect=False, retries=0):
    # uma porta UDP por chamada
    # retries so vale pra open|filtered, porque open/closed ja sao conclusivos
    result = {
        "port": port,
        "proto": "udp",
        "state": "open|filtered",
        "service": None,
        "banner": None,
        "confidence": 0.0,
    }

    payload = _payload_for(port) if service_detect else b""
    tentativas = retries + 1
    last_state = "open|filtered"
    last_data = b""

    for _ in range(tentativas):
        state, data = _one_probe(ip, port, timeout, payload)
        last_state = state
        last_data = data
        # open ou closed ja decidem
        if state in ("open", "closed"):
            break
        # open|filtered, tenta de novo se tiver retry

    result["state"] = last_state
    if last_data:
        result["banner"] = last_data[:80].decode("latin-1", "ignore").strip()

    return result