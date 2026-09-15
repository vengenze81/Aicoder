#!/usr/bin/env python3
"""
Memory usage monitor that parses /proc/meminfo using only the standard library.
"""

import argparse
import pathlib
import sys


def parse_meminfo(path: pathlib.Path = pathlib.Path("/proc/meminfo")) -> dict:
    """
    Parse /proc/meminfo into a dictionary of {key: value_in_bytes}.
    """
    meminfo = {}
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                key, rest = line.split(":", 1)
                value_str = rest.strip().split()[0]  # numeric part
                unit = rest.strip().split()[1] if len(rest.strip().split()) > 1 else "kB"
                # Convert everything to bytes for consistency
                try:
                    value = int(value_str)
                except ValueError:
                    continue
                if unit.lower() == "kb":
                    value *= 1024
                elif unit.lower() == "mb":
                    value *= 1024 ** 2
                elif unit.lower() == "gb":
                    value *= 1024 ** 3
                meminfo[key] = value
    except FileNotFoundError:
        sys.stderr.write(f"Error: {path} not found. This script works on Linux systems with /proc.\n")
        sys.exit(1)
    return meminfo


def format_bytes(num_bytes: int, human: bool = True) -> str:
    """Return a human‑readable string for a byte count."""
    if not human:
        return f"{num_bytes}"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num_bytes < 1024.0 or unit == "TB":
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"


def compute_usage(meminfo: dict) -> dict:
    """
    Compute total, used, free and usage percentage.
    Preference is given to MemAvailable when present (more accurate on modern kernels).
    """
    total = meminfo.get("MemTotal")
    if total is None:
        raise RuntimeError("MemTotal not found in /proc/meminfo")
    available = meminfo.get("MemAvailable")
    if available is not None:
        used = total - available
        free = available
    else:
        # Fallback to older calculation: used = total - MemFree - Buffers - Cached
        free = meminfo.get("MemFree", 0)
        buffers = meminfo.get("Buffers", 0)
        cached = meminfo.get("Cached", 0) + meminfo.get("SReclaimable", 0)
        used = total - free - buffers - cached
        free = free + buffers + cached
    percent = (used / total) * 100 if total else 0
    return {
        "total": total,
        "used": used,
        "free": free,
        "percent": percent,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Display system memory usage by parsing /proc/meminfo."
    )
    parser.add_argument(
        "-H",
        "--no-human",
        action="store_true",
        help="Print raw byte values instead of human‑readable units.",
    )
    args = parser.parse_args()

    meminfo = parse_meminfo()
    stats = compute_usage(meminfo)

    human = not args.no_human
    print("Memory Usage:")
    print(f"  Total: {format_bytes(stats['total'], human)}")
    print(f"  Used : {format_bytes(stats['used'], human)} ({stats['percent']:.2f}%)")
    print(f"  Free : {format_bytes(stats['free'], human)}")


if __name__ == "__main__":
    main()