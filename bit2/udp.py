# motor de scan UDP
# truque do connect: sem connect, o kernel engole o ICMP port-unreachable
# e a gente nunca ve a porta como closed. com connect, ele entrega
# como ECONNREFUSED no proximo recvfrom

import socket

from .signatures import UDP_PAYLOADS


def _payload_for(port):
    # devolve payload conhecido ou vazio
    return UDP_PAYLOADS.get(port, b"")


def scan_udp_port(ip, port, timeout, service_detect=False):
    # uma porta UDP por chamada
    result = {"port": port, "proto": "udp", "state": "open|filtered", "service": None, "banner": None}

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # connect em UDP nao faz handshake, so "cola" o socket no destino
        # e faz o kernel associar o ICMP daquela porta a este socket
        s.connect((ip, port))
        s.settimeout(timeout)

        payload = _payload_for(port) if service_detect else b""
        try:
            s.send(payload)
        except Exception:
            pass

        try:
            data = s.recv(2048)
            result["state"] = "open"
            if data:
                result["banner"] = data[:80].decode("latin-1", "ignore").strip()
        except socket.timeout:
            # sem resposta, nao da pra saber
            result["state"] = "open|filtered"
        except ConnectionRefusedError:
            # ICMP port unreachable -> porta fechada
            result["state"] = "closed"
        except OSError as e:
            if getattr(e, "errno", None) == 111:
                result["state"] = "closed"
            else:
                result["state"] = "open|filtered"
    except Exception:
        result["state"] = "open|filtered"
    finally:
        try:
            s.close()
        except Exception:
            pass
    return result
