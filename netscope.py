#!/usr/bin/env python3
"""NetScope: a small, permission-based TCP service checker for lab use."""
import argparse
import json
import socket
import sys
from datetime import datetime, timezone

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
}

def parse_ports(value):
    """Parse comma-separated ports and inclusive ranges."""
    ports = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            pieces = part.split("-", 1)
            if not all(piece.isdigit() for piece in pieces):
                raise ValueError(f"Invalid port range: {part}")
            start, end = map(int, pieces)
            if start > end:
                raise ValueError(f"Range start exceeds end: {part}")
            ports.update(range(start, end + 1))
        else:
            if not part.isdigit():
                raise ValueError(f"Invalid port: {part}")
            ports.add(int(part))
    if not ports:
        raise ValueError("Specify at least one port")
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Ports must be between 1 and 65535")
    if len(ports) > 256:
        raise ValueError("Limit each scan to 256 ports")
    return sorted(ports)

def check_port(host, port, timeout=0.5):
    """Return True if a TCP connection succeeds, otherwise False."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False

def scan(host, ports, timeout=0.5):
    """Scan the explicitly supplied host and ports sequentially."""
    results = []
    for port in ports:
        is_open = check_port(host, port, timeout)
        results.append({
            "port": port,
            "state": "open" if is_open else "closed|filtered",
            "service": COMMON_PORTS.get(port, "unknown"),
        })
    return results

def main():
    parser = argparse.ArgumentParser(
        description="NetScope: basic TCP port checker for systems you own or have permission to test."
    )
    parser.add_argument("--target", required=True, help="One hostname or IP address you are authorized to test")
    parser.add_argument("--ports", default="22,80,443,8080", help='Ports, e.g. "22,80,443" or "1-100" (max 256)')
    parser.add_argument("--timeout", type=float, default=0.5, help="Connection timeout in seconds (default: 0.5)")
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    args = parser.parse_args()

    if not 0.1 <= args.timeout <= 3.0:
        parser.error("--timeout must be between 0.1 and 3 seconds")
    try:
        ports = parse_ports(args.ports)
        # Resolve once so the output identifies the actual address tested.
        address = socket.gethostbyname(args.target)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    print(f"NetScope | target: {args.target} ({address})")
    print("Authorization required: scan only systems you own or have permission to test.")
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    results = scan(address, ports, args.timeout)

    if args.json:
        print(json.dumps({"target": args.target, "address": address,
                          "started_utc": started, "results": results}, indent=2))
    else:
        print("\nPORT     STATE           SERVICE")
        print("-" * 38)
        for item in results:
            print(f'{item["port"]:<8} {item["state"]:<15} {item["service"]}')
        print(f"\nChecked {len(results)} TCP ports.")

if __name__ == "__main__":
    main()
