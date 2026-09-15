#!/usr/bin/env python3
"""
Check common local ports (80, 443, 8080) on localhost using only the
built‑in socket standard library.
"""

import socket
from typing import List

HOST = "127.0.0.1"
PORTS: List[int] = [80, 443, 8080]
TIMEOUT = 1.0  # seconds


def is_port_open(host: str, port: int, timeout: float = TIMEOUT) -> bool:
    """
    Return True if a TCP connection to (host, port) can be established within
    the given timeout; otherwise return False.
    """
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def main() -> None:
    for port in PORTS:
        if is_port_open(HOST, port):
            status = "OPEN"
        else:
            status = "closed"
        print(f"Port {port} on {HOST} is {status}")


if __name__ == "__main__":
    main()