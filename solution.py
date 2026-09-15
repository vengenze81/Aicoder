#!/usr/bin/env python3
"""
Gather basic system and network configuration details using only the standard library.
Details collected:
- Hostname
- Primary IP address
- OS platform information
- Python version
"""

import socket
import platform
import sys


def get_hostname() -> str:
    """Return the system's hostname."""
    return socket.gethostname()


def get_primary_ip() -> str:
    """
    Determine the primary IP address used for outbound connections.
    This method creates a temporary UDP socket to a well‑known external address
    (Google DNS) without sending any data, then reads the socket's own address.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # The IP/port here does not need to be reachable; no packets are sent.
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        # Fallback to localhost if we cannot determine an external address
        return "127.0.0.1"


def get_os_info() -> str:
    """Return a string describing the operating system."""
    return f"{platform.system()} {platform.release()} ({platform.version()})"


def get_python_version() -> str:
    """Return the current Python interpreter version."""
    return sys.version.splitlines()[0]  # e.g., '3.11.8 (main, Mar  5 2024, ...)'

def main() -> None:
    print("System Configuration Details")
    print("-" * 30)
    print(f"Hostname          : {get_hostname()}")
    print(f"Primary IP address: {get_primary_ip()}")
    print(f"OS Platform       : {get_os_info()}")
    print(f"Python version    : {get_python_version()}")


if __name__ == "__main__":
    main()