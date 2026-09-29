# cores e helpers de terminal
# tudo que mexe com ANSI fica aqui, pra nao espalhar sujeira

import os
import sys

R = "\033[0m"
B = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GRN = "\033[32m"
YEL = "\033[33m"
BLU = "\033[34m"
MAG = "\033[35m"
CYN = "\033[36m"

# sequencia ANSI pra limpar a linha toda, mais confiavel que contar espaco
CLR_LINE = "\033[2K\r"


def color_enabled():
    # se nao for tty, melhor nao sujar
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def c(txt, cor):
    # coloriza texto, respeitando NO_COLOR e tty
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
