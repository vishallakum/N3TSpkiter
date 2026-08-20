#!/usr/bin/env python3
"""
N3TSpkiter v4.0 - Advanced Network Reconnaissance Tool
52 Features | Full Interactive Shell
"""

import sys
import os
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def signal_handler(sig, frame):
    print("\n\033[93m[!] Use 'exit' to quit.\033[0m")


def main():
    signal.signal(signal.SIGINT, signal_handler)
    try:
        from core.shell import N3TSpkiterShell
        shell = N3TSpkiterShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n\033[96mExiting N3TSpkiter.\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[91m[ERROR] {str(e)}\033[0m")
        sys.exit(1)


if __name__ == "__main__":
    main()
