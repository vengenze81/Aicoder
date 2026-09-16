#!/usr/bin/env python3
"""
Advanced Recon Module – lightweight, thread-based port scanner.
"""

from __future__ import annotations
from tqdm import tqdm

import argparse
import csv
import json
import logging
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone, timezone
from pathlib import Path
from typing import Iterable, List, Optional, TypedDict

LOG = logging.getLogger(__name__)


def configure_logging(verbosity: int) -> None:
    level = max(logging.DEBUG, logging.WARNING - (verbosity * 10))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


class OpenService(TypedDict):
    port: int
    status: str
    banner: str


class ReconReport(TypedDict):
    target: str
    timestamp: str
    open_services: List[OpenService]


@dataclass
class ServiceInfo:
    port: int
    banner: str = "No banner returned"
    status: str = "open"

    def to_dict(self) -> OpenService:
        return {
            "port": self.port,
            "status": self.status,
            "banner": self.banner,
        }


class PenetrationTester:
    def __init__(
        self,
        target_host: str,
        ports: Iterable[int],
        max_threads: int = 10,
        socket_timeout: float = 1.5,
        probe: bool = True,
    ) -> None:
        self.target_host = target_host
        self.ports = list(sorted(set(ports)))
        self.max_threads = max_threads
        self.socket_timeout = socket_timeout
        self.probe = probe
        self.max_concurrency = 100

        try:
            self.addr_info = socket.getaddrinfo(
                self.target_host, None, proto=socket.IPPROTO_TCP
            )[0]
        except socket.gaierror as exc:
            LOG.error("Unable to resolve target %s: %s", self.target_host, exc)
            raise

        self._family = self.addr_info[0]
        self._socktype = self.addr_info[1]

        self.report: ReconReport = {
            "target": self.target_host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open_services": [],
        }

    @staticmethod
    def _http_probe(sock: socket.socket) -> None:
        try:
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        except OSError:
            pass

    @staticmethod
    def _smtp_probe(sock: socket.socket) -> None:
        try:
            sock.sendall(b"EHLO example.com\r\n")
        except OSError:
            pass

    @staticmethod
    def _ssh_probe(sock: socket.socket) -> None:
        pass

    def _select_probe(self, port: int) -> Optional[callable]:
        probes = {
            80: self._http_probe,
            443: self._http_probe,
            8080: self._http_probe,
            8443: self._http_probe,
            25: self._smtp_probe,
            587: self._smtp_probe,
            22: self._ssh_probe,
        }
        return probes.get(port)

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        sock.settimeout(self.socket_timeout)

        if self.probe:
            probe_func = self._select_probe(port)
            if probe_func:
                probe_func(sock)

        try:
            raw = sock.recv(1024)
            if not raw:
                return "No banner returned"
            return raw.decode(errors="ignore").strip()
        except (socket.timeout, OSError):
            return "No banner returned"

    def scan_port(self, port: int) -> Optional[ServiceInfo]:
        try:
            with socket.socket(self._family, self._socktype, socket.IPPROTO_TCP) as sock:
                sock.settimeout(self.socket_timeout)
                result = sock.connect_ex((self.addr_info[4][0], port))

                if result != 0:
                    return None

                banner = self._grab_banner(sock, port)
                LOG.info("Port %d OPEN – banner: %s", port, banner)
                return ServiceInfo(port=port, banner=banner)

        except Exception as exc:
            LOG.debug("Unexpected error scanning port %d: %s", port, exc)
            return None

    def run_recon(self, deadline: Optional[float] = None) -> None:
        LOG.info("Starting reconnaissance on %s (%d ports)", self.target_host, len(self.ports))

        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, p): p for p in self.ports
            }

            for future in tqdm(as_completed(future_to_port), total=len(self.ports), desc="Scanning"):
                if deadline is not None and time.time() > deadline:
                    LOG.warning("Global scan deadline reached – aborting remaining jobs")
                    break

                port = future_to_port[future]
                try:
                    service = future.result()
                except Exception as exc:
                    LOG.debug("Exception while scanning port %d: %s", port, exc)
                    continue

                if service:
                    self.report["open_services"].append(service.to_dict())

        elapsed = time.time() - start_time
        LOG.info(
            "Recon finished in %.2fs – %d open services found",
            elapsed,
            len(self.report["open_services"]),
        )

    def export_csv(self, filename: Path) -> None:
        try:
            filename.parent.mkdir(parents=True, exist_ok=True)
            with filename.open("w", newline="", encoding="utf-8") as fp:
                writer = csv.writer(fp)
                writer.writerow(["Port", "Status", "Banner"])
                for service in self.report["open_services"]:
                    writer.writerow([service["port"], service["status"], service["banner"]])
            LOG.info("CSV Report written to %s", filename)
        except OSError as exc:
            LOG.error("Failed to write CSV report: %s", exc)
            raise

    def export_report(self, filename: Path) -> None:
        try:
            filename.parent.mkdir(parents=True, exist_ok=True)
            with filename.open("w", encoding="utf-8") as fp:
                json.dump(self.report, fp, indent=4, ensure_ascii=False)
            LOG.info("Report written to %s", filename)
        except OSError as exc:
            LOG.error("Failed to write report: %s", exc)
            raise


def _parse_ports(port_str: str) -> List[int]:
    ports: List[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            try:
                start, end = int(start_s), int(end_s)
                if not (0 < start <= 65535 and 0 < end <= 65535):
                    raise ValueError
                ports.extend(range(start, end + 1))
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port range: {part}")
        else:
            try:
                p = int(part)
                if not (0 < p <= 65535):
                    raise ValueError
                ports.append(p)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port: {part}")
    return sorted(list(set(ports)))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Advanced Recon Module – lightweight concurrent port scanner."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        default="22,80,443,8080",
        help="Comma-separated ports or ranges (e.g. 22,80,8000-8010)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Maximum concurrent threads (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Socket timeout in seconds (default: 1.5)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Path to save JSON report output",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase output verbosity (-v, -vv)",
    )

    args = parser.parse_args()
    configure_logging(args.verbose)

    try:
        parsed_ports = _parse_ports(args.ports)
        tester = PenetrationTester(
            target_host=args.target,
            ports=parsed_ports,
            max_threads=args.threads,
            socket_timeout=args.timeout,
        )
        tester.run_recon()

        if args.output:
            if args.output.suffix.lower() == ".csv":
                tester.export_csv(args.output)
            else:
                tester.export_report(args.output)
        else:
            print(json.dumps(tester.report, indent=4))

    except KeyboardInterrupt:
        LOG.warning("Scan interrupted by user.")
        sys.exit(1)
    except Exception as exc:
        LOG.error("Fatal error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
