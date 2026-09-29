#!/usr/bin/env python3
# entry point do bit2
# a magica toda mora no pacote bit2/, aqui so chama

import sys

from bit2.cli import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
