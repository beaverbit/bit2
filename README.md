# bit2

> Scanner de rede CLI escrito em Python puro, sem dependências externas.
> Feito pra ser rápido, legível e útil de verdade na linha de comando.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Sobre

`bit2` é um scanner de rede inspirado no `nmap`, construído do zero usando apenas a biblioteca padrão do Python. O objetivo é ser uma alternativa leve para reconhecimento rápido de rede, com foco em:

- **Zero dependências** — só `stdlib`, roda em qualquer máquina com Python 3.8+
- **CLI-first** — sem GUI, sem config file, só flags diretas
- **Multi-protocolo** — TCP connect scan e UDP scan
- **Classificação precisa** — `open` / `closed` / `filtered` (alinhado com nmap)
- **Output flexível** — tabela colorida, XML (nmap-like), grep ou JSON
- **Scan concorrente** — varredura paralela via `ThreadPoolExecutor`

Foi escrito como exercício de sistemas + redes, e acabou virando uma ferramenta que uso no dia a dia.

---

## Features

| Feature | Status |
|---|---|
| TCP connect scan com classificação `open`/`closed`/`filtered` | ✅ |
| UDP scan com detecção de `closed` via ICMP | ✅ |
| Retry configurável em portas filtered (`--retry N`) | ✅ |
| Concorrência via threads (`concurrent.futures`) | ✅ |
| Top 100 portas TCP + top UDP (baseado no nmap) | ✅ |
| Range customizado (`1-1024`, `22,80,8000-8100`) | ✅ |
| CIDR (`192.168.0.0/24`) + range de IP (`10.0.0.1-20`) + lista | ✅ |
| Host discovery TCP (sem root) | ✅ |
| Banner grabbing com probe por porta | ✅ |
| Identificação de serviço por assinatura regex com confidence | ✅ |
| Output tabelado com ANSI colors | ✅ |
| Output XML compatível com nmap | ✅ |
| Output grep-friendly pra pipeline | ✅ |
| Export JSON estruturado | ✅ |
| Progress bar (TTY-aware) | ✅ |
| Modo live (streaming) e ordenado (buffer) | ✅ |
| Resolução DNS + reverse DNS | ✅ |

---

## Instalação

### Requisitos

- Python 3.8 ou superior
- Nenhum pacote externo

### Setup via pip (recomendado)

```bash
git clone https://github.com/beaverbit/bit2.git
cd bit2
pip install -e .
```

Isso instala o comando `bit2` no seu PATH (usa o `pyproject.toml`).

### Setup via cópia

Se não quiser usar pip:

```bash
git clone https://github.com/beaverbit/bit2.git
cd bit2
# torna o wrapper executavel
chmod +x bit2.sh
make install-global   # copia pra /usr/local/bin
```

Ou roda direto do diretório (sem `chmod`):

```bash
bash bit2.sh --top -sV scanme.nmap.org
# ou
python3 bit2.py --top -sV scanme.nmap.org
```

### Nota sobre `make`

O `Makefile` é opcional — só facilita a vida de quem desenvolve. Se você não tem `make` instalado:

```bash
# debian/ubuntu
sudo apt install make

# fedora
sudo dnf install make

# arch
sudo pacman -S make
```

Sem `make`, use `pytest` diretamente:

```bash
pytest -q
pytest --cov=bit2 --cov-report=term-missing
python3 -m py_compile bit2.py bit2/*.py
```

---

## Uso

### Sintaxe básica

```
bit2 [flags] <host>
```

O `<host>` aceita:

- Host único: `192.168.0.1`, `scanme.nmap.org`
- CIDR: `192.168.0.0/24`
- Range de IP: `10.0.0.1-10.0.0.20`
- Lista com vírgula: `10.0.0.1,10.0.0.5,scanme.nmap.org`
- Mix de tudo acima

### Exemplos

```bash
# top 100 portas TCP com detecção de serviço (default)
bit2 scanme.nmap.org

# UDP scan nas portas top
bit2 -sU --top-udp 127.0.0.1

# UDP + TCP juntos
bit2 -sU --also-tcp --top -sV scanme.nmap.org

# varredura de rede inteira com discovery automático
bit2 --top 192.168.0.0/24

# range de IP
bit2 -p 1-1024 10.0.0.1-10.0.0.20

# lista mista
bit2 --top 10.0.0.1,10.0.0.5,scanme.nmap.org

# output XML (importável em ferramentas tipo Metasploit)
bit2 --top -sV --output xml scanme.nmap.org > out.xml

# output grep (fácil de filtrar com awk/grep)
bit2 --top -sV --output grep scanme.nmap.org

# salva resultado em JSON
bit2 --top -sV --json out.json scanme.nmap.org

# lê alvos de um arquivo
bit2 --target-file hosts.txt --top

# lê portas de um arquivo
bit2 --port-file ports.txt -sV scanme.nmap.org

# retry em portas filtered (útil em redes com packet loss)
bit2 -p 22,80,443 --retry 2 -T 0.5 alvo.com

# modo live (streaming, sem ordenar)
bit2 --live -sV scanme.nmap.org

# modo verboso, mostra portas fechadas e filtradas também
bit2 -p 1-100 -v 10.0.0.1

# desabilitar cor (útil pra log em arquivo)
bit2 --no-color --top alvo.com
```

### Output de exemplo

```
bit2 scan report for scanme.nmap.org
----------------------------------------------------
IP:       45.33.32.156
rDNS:     scanme.nmap.org
Portas:   100
Proto:    tcp
Threads:  100
Timeout:  1.5s
----------------------------------------------------
PORT                STATE         SERVICE     VERSION
22/tcp              open          SSH         SSH-2.0-OpenSSH_6.6.1p1
80/tcp              open          HTTP        HTTP/1.1 200
----------------------------------------------------
abertas: 2/100  1 filtradas  (1.55s)
```

### Output grep

Formato: `ip:porta:proto:estado:servico:confidence:banner`

```
45.33.32.156:22:tcp:open:SSH:1.00:SSH-2.0-OpenSSH_6.6.1p1
45.33.32.156:80:tcp:open:HTTP:0.98:HTTP/1.1 200
```

### Output XML

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="bit2" version="0.3.0" start="1790701317" args="bit2">
  <host>
    <status state="up"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <hostnames><hostname name="scanme.nmap.org"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" version="SSH-2.0-OpenSSH_6.6.1p1" conf="1.00"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" version="HTTP/1.1 200" conf="0.98"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

---

## Flags

| Flag | Descrição | Default |
|---|---|---|
| `host` | Alvo (host, CIDR, range, lista) ou posicional | obrigatório (ou `--target-file`) |
| `--target-file FILE` | Arquivo com alvos (um por linha) | — |
| `-p, --ports` | Spec de portas: `80`, `80,443`, `1-1024`, `22,80,8000-8100` | top 100 TCP |
| `--port-file FILE` | Arquivo com portas (uma por linha ou spec) | — |
| `--top` | Força a top 100 TCP | — |
| `--top-udp` | Força a top UDP | — |
| `-sU, --udp` | Ativa modo UDP (só UDP, por padrão) | off |
| `--also-tcp` | Com `-sU`, escaneia TCP também | off |
| `-t, --threads` | Threads concorrentes | `100` |
| `-T, --timeout` | Timeout por porta em segundos | `1.5` |
| `--retry N` | Tentativas extras em portas `filtered` | `0` |
| `-sV, --service` | Banner grabbing + detecção de serviço | off |
| `--json FILE` | Salva resultado em JSON | — |
| `--output MODE` | Formato de saída: `normal`, `xml`, `grep` | `normal` |
| `-v, --verbose` | Mostra portas fechadas e filtradas (só modo normal) | off |
| `--open-only` | Suprime tudo que não estiver aberto | off |
| `--live` | Imprime em tempo real (sem ordenar) | off |
| `--no-progress` | Desabilita barra de progresso | off |
| `--no-color` | Desabilita ANSI colors | off |
| `--skip-discovery` | Pula host discovery em multi-alvo | off |
| `--discovery-ports` | Portas do discovery | `80,443,22,8080,3389,445` |
| `--version` | Mostra versão | — |

---

## Arquitetura

### Estrutura de arquivos

```
bit2/
├── bit2/                  # pacote principal
│   ├── __init__.py        # versão
│   ├── cli.py             # argparse + main()
│   ├── colors.py          # helpers ANSI
│   ├── scanner.py         # TCP connect + classificação + discovery
│   ├── udp.py             # UDP scan com ICMP detection
│   ├── signatures.py      # TOP_PORTS, SIGS (com confidence), PROBES, UDP_PAYLOADS
│   ├── targets.py         # parsing de alvos/portas + discovery
│   └── output.py          # formatadores (xml, grep, is_open)
├── tests/                 # suite pytest (65 testes)
│   ├── test_targets.py    # parsing
│   ├── test_scanner.py    # TCP scan + classificação (mock)
│   ├── test_udp.py        # UDP scan (mock)
│   ├── test_output.py     # formatadores
│   └── test_integration.py # servidor TCP/UDP local
├── .github/workflows/
│   └── ci.yml             # GitHub Actions
├── bit2.py                # entry point (trivial)
├── bit2.sh                # wrapper shell (rode `chmod +x bit2.sh` após clonar)
├── Makefile               # atalhos (make test, make lint, make ci)
├── pyproject.toml         # empacotamento + config de testes
├── SECURITY.md            # política de segurança
└── README.md
```

### Fluxo de execução

```
1. argparse parseia flags
2. parse_targets() resolve host/CIDR/range/lista → [(label, ip), ...]
3. parse_ports() normaliza spec de portas
4. Se multi-alvo e não --skip-discovery: discover_hosts() filtra vivos
5. ThreadPoolExecutor dispara _dispatch() para cada (proto, port)
6. scan_port() (TCP) ou scan_udp_port() (UDP) rodam em threads
7. Resultados coletados via as_completed()
8. Modo normal: sort() + print. Modo xml/grep: só coleta e formata no fim
9. --json serializa payload final
```

### Decisões de design

**Por que `ThreadPoolExecutor` e não `asyncio`?**
`connect_ex()` é blocking. Refatorar pra `asyncio` exigiria reescrever `grab_banner`, `recv`, etc. — overhead que não traz ganho real pra esse caso (o gargalo é I/O de rede, não CPU). Threads resolvem bem.

**Por que TCP connect scan e não SYN scan?**
SYN scan precisa de raw socket + root. Connect scan funciona sem privilégio algum, é mais portável (macOS, WSL, containers). A trade-off é ser mais "ruidoso" (gera log no alvo), mas pra reconhecimento isso é aceitável.

**Por que classificar `filtered` separado de `closed`?**
`connect_ex()` retorna um errno por porta. `ECONNREFUSED` significa que o host respondeu com RST — porta fechada. `ETIMEDOUT`, `EHOSTUNREACH`, `ENETUNREACH` significam que nada voltou (firewall dropou ou rota ruim) — porta filtrada. Tratar tudo como `closed` é simplificação perigosa: você perde a informação de que existe firewall no caminho. O nmap usa exatamente essa separação.

**Por que UDP scan usa `connect()` antes de `send()`?**
Sem `connect()`, o kernel Linux engole o ICMP port-unreachable e o socket nunca vê `ECONNREFUSED`. Com `connect()` (que em UDP é só associar destino, sem handshake), o kernel entrega o ICMP corretamente no próximo `recv()`. Sem isso, toda porta UDP fechada vira `open|filtered` — mentira.

**Por que assinatura de banner tem campo de confidence?**
Algumas assinaturas são mais específicas que outras. SSH começa com `SSH-2.0-` — é praticamente 100% de certeza. HTTP também é altíssimo. Mas algo como `MongoDB` (que casa com qualquer coisa que tenha 4 bytes seguidos de 3 nulls) é mais frágil. O campo `confidence` deixa o consumidor (você, uma ferramenta downstream, um script) decidir se confia. Fica no JSON e XML mas não polui o output normal.

**Por que assinatura de banner por regex e não heurística mais sofisticada?**
O objetivo é cobertura ampla com complexidade baixa. Um dicionário de regexes cobre ~80% dos casos reais. Fingerprinting profundo (tipo `nmap -sV`) exigiria uma base enorme de probes customizados — fora do escopo.

**Por que `PROBES` só inclui portas HTTP-like (não TLS)?**
Mandar `HEAD / HTTP/1.0` num socket TLS quebra o handshake e o servidor responde 400 (foi exatamente o que aconteceu no `python3 -m http.server` durante os testes). Por isso `443`, `8443` e `9443` ficam de fora: o `bit2` só recebe (espera banner espontâneo) em vez de enviar probe em claro.

**Por que cor só quando `isatty()`?**
Pra não sujar output quando redirecionado (`bit2 ... > out.txt`). Regra padrão de CLIs bem-comportados. Também respeita `NO_COLOR` env var (convenção do https://no-color.org). **A barra de progresso não depende de cor** — só de `isatty()`, pra funcionar mesmo com `--no-color`.

**Por que XML só com portas relevantes?**
XML é pra consumo por ferramentas, não debug humano. Portas `closed` e `filtered` poluem e não interessam. `-v` no modo XML vira no-op — quem quer debug usa modo normal.

---

## Limitações conhecidas

- **Sem SYN scan (half-open)** — apenas connect scan; requer root + raw socket
- **Sem detecção de OS** — fingerprinting por TTL/options ficou fora do escopo
- **Sem IPv6** — apenas IPv4 (`AF_INET`)
- **Banner grabbing passivo** — não envia probes customizados pra todos os serviços, apenas pros que estão mapeados em `PROBES`/`HTTP_LIKE_PORTS`
- **UDP sem root é impreciso** — portas `closed` só são detectadas se o ICMP port-unreachable chegar. Sem root, `open|filtered` pode ser tanto porta filtrada quanto aberta que não respondeu
- **Scheduler global não é paralelo entre hosts** — em scans multi-alvo, cada host é processado sequencialmente (portas dentro do host são paralelas). Vale otimização futura pra redes grandes
- **`-t` alto pode atingir file descriptor limit** — se rodar em sistema com `ulimit -n` baixo, use `ulimit -n 4096` antes
- **`make install` requer Python com suporte a `venv`** — em distros com PEP 668 (Ubuntu 24+), usar venv antes
- **`bit2.sh` precisa de `chmod +x`** após clonar (git não preserva bit de execução em alguns casos)

---

## Desenvolvimento

### Setup do ambiente

```bash
git clone https://github.com/beaverbit/bit2.git
cd bit2
chmod +x bit2.sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Comandos

```bash
make test         # roda pytest
make test-cov     # pytest + cobertura
make lint         # valida sintaxe py + sh
make fmt          # roda black (se instalado)
make ci           # lint + test (o que a CI roda)
make clean        # limpa pycache, coverage, build
```

Sem `make`:

```bash
pytest -q
pytest --cov=bit2 --cov-report=term-missing
python3 -m py_compile bit2.py bit2/*.py
bash -n bit2.sh
```

### CI

Roda em todo push pra `main` e em PRs:

- **lint** — valida sintaxe de `bit2.py`, `bit2/*.py` e `bit2.sh`
- **test** — pytest em Python **3.8**, **3.10** e **3.12**

Configuração em [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## Roadmap

- [x] CIDR + range de IP + lista de alvos
- [x] Host discovery TCP
- [x] UDP scan básico
- [x] Output XML (nmap-like)
- [x] Output grep
- [x] Testes unitários com `pytest`
- [x] Testes de integração com servidor local
- [x] CI via GitHub Actions
- [x] Classificação TCP precisa (`open`/`closed`/`filtered`)
- [x] Retry em timeout (`--retry N`)
- [ ] Timing templates (`-T0` a `-T5`)
- [ ] SYN scan opcional (requer root)
- [ ] Fingerprint de OS via TTL e TCP window size
- [ ] Scheduler global multi-host (paralelismo entre hosts)
- [ ] IPv6
- [ ] Diff entre scans (`--diff`)
- [ ] Publicação no PyPI
- [ ] Dockerfile
- [ ] Release automatizado

---

## Aviso legal

`bit2` é uma ferramenta de reconhecimento. **Só use em redes que você possui ou tem autorização explícita por escrito para escanear.** Escanear redes de terceiros sem permissão é crime em diversas jurisdições (no Brasil, enquadra-se na Lei 12.737/2012 — "Lei Carolina Dieckmann" — e no Marco Civil da Internet).

O autor não se responsabiliza por uso indevido.
