# bit2

> Port scanner CLI escrito em Python puro, sem dependências externas.
> Feito pra ser rápido, legível e útil de verdade na linha de comando.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)
![Dependencies](https://img.shields.io/badge/dependencies-zero-success)

---

## Sobre

`bit2` é um scanner de portas TCP inspirado no `nmap`, construído do zero usando apenas a biblioteca padrão do Python. O objetivo é ser uma alternativa leve para reconhecimento rápido de rede, com foco em:

- **Zero dependências** — só `stdlib`, roda em qualquer máquina com Python 3.8+
- **CLI-first** — sem GUI, sem config file, só flags diretas
- **Output legível** — tabela colorida estilo nmap, ou JSON pra pipeline
- **Scan concorrente** — varredura paralela via `ThreadPoolExecutor`

Foi escrito como exercício de sistemas + redes, e acabou virando uma ferramenta que uso no dia a dia.

---

## Features

| Feature | Status |
|---|---|
| TCP connect scan (`connect_ex`) | ✅ |
| Concorrência via threads (`concurrent.futures`) | ✅ |
| Top 100 portas hardcoded (baseado no nmap) | ✅ |
| Range customizado (`1-1024`, `22,80,8000-8100`) | ✅ |
| Banner grabbing com probe por porta | ✅ |
| Identificação de serviço por assinatura regex | ✅ |
| Output tabelado com ANSI colors | ✅ |
| Progress bar (TTY-aware) | ✅ |
| Modo live (streaming) e ordenado (buffer) | ✅ |
| Export JSON | ✅ |
| Resolução DNS + reverse DNS | ✅ |

---

## Instalação

### Requisitos

- Python 3.8 ou superior
- Nenhum pacote externo

### Setup

```bash
git clone https://github.com/beaverbit/bit2.git
cd bit2
make install
```

O `make install` copia o `bit2.py` e o `bit2.sh` para `/usr/local/bin`. Se não quiser instalar globalmente, pode usar direto:

```bash
./bit2.sh --top -sV scanme.nmap.org
```

---

## Uso

### Sintaxe básica

```
bit2 [flags] <host>
```

### Exemplos

```bash
# top 100 portas com detecção de serviço (default)
bit2 scanme.nmap.org

# varredura de range específico
bit2 -p 1-1024 -sV 10.0.0.1

# portas específicas + range misto
bit2 -p 22,80,443,8000-8100 -t 200 192.168.0.1

# salva resultado em JSON pra processar depois
bit2 --top -sV --json out.json alvo.com

# modo live (streaming), sem ordenar por porta
bit2 --live -sV scanme.nmap.org

# modo verboso, mostra portas fechadas também
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
Threads:  100
Timeout:  1.5s
----------------------------------------------------
PORT                STATE       SERVICE     VERSION
22/tcp              open        SSH         SSH-2.0-OpenSSH_6.6.1p1
80/tcp              open        HTTP        HTTP/1.1 200
----------------------------------------------------
abertas: 2/100  (1.55s)
```

---

## Flags

| Flag | Descrição | Default |
|---|---|---|
| `-p, --ports` | Spec de portas: `80`, `80,443`, `1-1024`, `22,80,8000-8100` | top 100 |
| `--top` | Força a top 100 (explícito) | — |
| `-t, --threads` | Número de threads concorrentes | `100` |
| `-T, --timeout` | Timeout por porta em segundos | `1.5` |
| `-sV, --service` | Habilita banner grabbing + detecção de serviço | off |
| `--json FILE` | Salva resultado em JSON estruturado | — |
| `-v, --verbose` | Mostra portas fechadas também | off |
| `--open-only` | Suprime tudo que não estiver aberto | off |
| `--live` | Imprime conforme chega (sem ordenar) | off |
| `--no-progress` | Desabilita barra de progresso | off |
| `--no-color` | Desabilita ANSI colors | off |

---

## Arquitetura

### Estrutura de arquivos

```
bit2/
├── bit2.py         # código principal (single-file)
├── bit2.sh         # wrapper shell (checa python, versão mínima)
├── Makefile        # atalhos de dev/install
├── README.md       # este arquivo
└── .gitignore
```

### Fluxo de execução

```
1. argparse parseia flags
2. resolve() converte host → IP (socket.gethostbyname)
3. parse_ports() normaliza spec de portas
4. ThreadPoolExecutor dispara scan_port() para cada porta
5. scan_port() faz connect_ex(), se aberto → grab_banner() → identify()
6. Resultados coletados via as_completed()
7. Modo default: sort() + print. Modo --live: print imediato.
8. Se --json: serializa payload
```

### Decisões de design

**Por que `ThreadPoolExecutor` e não `asyncio`?**
`connect_ex()` é blocking. Refatorar pra `asyncio` exigiria reescrever `grab_banner`, `recv`, etc. — overhead que não traz ganho real pra esse caso (o gargalo é I/O de rede, não CPU). Threads resolvem bem.

**Por que TCP connect scan e não SYN scan?**
SYN scan precisa de raw socket + root. Connect scan funciona sem privilégio algum, é mais portável (macOS, WSL, containers). A trade-off é ser mais "ruidoso" (gera log no alvo), mas pra reconhecimento isso é aceitável.

**Por que assinatura de banner por regex e não heurística mais sofisticada?**
O objetivo é cobertura ampla com complexidade baixa. Um dicionário de regexes cobre ~80% dos casos reais. Fingerprinting profundo (tipo `nmap -sV`) exigiria uma base enorme de probes customizados — fora do escopo.

**Por que cor só quando `isatty()`?**
Pra não sujar output quando redirecionado (`bit2 ... > out.txt`). Regra padrão de CLIs bem-comportados. Também respeita `NO_COLOR` env var (convenção do https://no-color.org).

---

## Limitações conhecidas

- **UDP não suportado** — apenas TCP connect scan
- **Sem detecção de OS** — fingerprinting por TTL/options ficou fora do escopo inicial
- **Sem output XML** — apenas JSON (por enquanto)
- **Sem IPv6** — apenas IPv4 (`AF_INET`)
- **Sem alvos múltiplos / CIDR** — um host por invocação
- **Banner grabbing passivo** — não envia probes customizados pra todos os serviços, apenas pros que estão mapeados em `PROBES`
- **`-t` alto pode atingir file descriptor limit** — se rodar em sistema com `ulimit -n` baixo, use `ulimit -n 4096` antes

---

## Roadmap

- [ ] Suporte a CIDR (`10.0.0.0/24`) com host discovery
- [ ] UDP scan básico (DNS, SNMP, NTP)
- [ ] Output XML compatível com `nmap` (importável no Metasploit)
- [ ] SYN scan opcional (requer root)
- [ ] Fingerprint de OS via TTL e TCP window size
- [ ] Testes unitários com `pytest`
- [ ] CI via GitHub Actions (lint + smoke test)

---

## Desenvolvimento

```bash
make lint      # valida sintaxe py + sh
make test      # roda smoke test
make clean     # limpa pycache e json
```

---

## Aviso legal

`bit2` é uma ferramenta de reconhecimento. **Só use em redes que você possui ou tem autorização explícita por escrito para escanear.** Escanear redes de terceiros sem permissão é crime em diversas jurisdições (no Brasil, enquadra-se na Lei 12.737/2012 — "Lei Carolina Dieckmann" — e no Marco Civil da Internet).

O autor não se responsabiliza por uso indevido.

---

## Licença

MIT — faz o que quiser, só não me processa.
