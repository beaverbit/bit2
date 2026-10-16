#!/usr/bin/env python3
# entry point do bit2

import sys

from bit2.cli import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
