# bit2

Scanner de porta via linha de comando.

## O que faz

- TCP connect scan com threads
- Top 100 portas (padrao) ou range customizado
- Banner grabbing + deteccao de servico (SSH, HTTP, FTP, MySQL, Redis, etc)
- Output colorido estilo nmap
- Exporta em JSON

## Instalacao

So precisa de Python 3.8+. Sem dependencia externa.

```bash
git clone https://github.com/<seu-user>/bit2.git
cd bit2
make install
```

## Uso

```bash
bit2 192.168.0.1
bit2 -p 1-1024 -sV scanme.nmap.org
bit2 -p 22,80,443,8000-8100 -t 200 10.0.0.1
bit2 --top -sV --json out.json alvo.com
```

## Flags

| flag | o que faz |
|------|-----------|
| `-p` | portas (`80`, `80,443`, `1-1024`, `22,80,8000-8100`) |
| `--top` | top 100 portas |
| `-t` | threads (default 100) |
| `-T` | timeout em segundos (default 1.5) |
| `-sV` | detecta servico/banner |
| `--json FILE` | salva resultado em json |
| `-v` | mostra porta fechada tambem |
| `--open-only` | so porta aberta |
| `--no-color` | sem cor |

## Aviso

Só usa em rede que você tem autorização. Escanear rede dos outros sem permissão é crime em vários lugares.
