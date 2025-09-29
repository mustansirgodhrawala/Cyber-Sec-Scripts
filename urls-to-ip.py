#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# resolver.py
#
# Author: Mustansir Godhrawala <me@mustansirg.in>
# License: GNU General Public License v3.0 (GPLv3)
#
# Description:
#   Resolve URLs/hostnames into IP addresses for use with tools like nmap.
#   - Supports input from file or CLI
#   - Ignores '#' comments in input files
#   - Outputs either TXT (nmap-friendly IP list with comments) or CSV
#   - Optional sound alert when finished
# -----------------------------------------------------------------------------

import argparse
import socket
import csv
import sys
from pathlib import Path


def resolve_hostname(hostname: str) -> str | None:
    """Try to resolve a hostname into an IP, return None on failure."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def read_urls_from_file(filepath: str) -> list[str]:
    """Read URLs/hostnames from the given file, ignoring # comments and blanks."""
    urls = []
    file_path = Path(filepath)

    if not file_path.exists():
        print(f"[ERROR] File not found: {filepath}")
        return urls

    with file_path.open() as f:
        for line in f:
            line = line.strip()
            # Skip comments/empty lines
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def save_results(output_file: str, resolved: dict[str, str], unresolved: list[str]):
    """Save results into TXT (nmap-style) or CSV based on extension."""
    path = Path(output_file)
    ext = path.suffix.lower()

    if ext == ".csv":
        with path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Hostname", "IP"])
            for host, ip in resolved.items():
                writer.writerow([host, ip])
            for host in unresolved:
                writer.writerow([host, "UNRESOLVED"])
        print(f"[+] Results written to {output_file} (CSV format)")
    else:  # Default: TXT output, IP list with comments
        with path.open("w") as f:
            for host, ip in resolved.items():
                f.write(f"# {host}\n{ip}\n")
            if unresolved:
                f.write("\n# === Unresolved ===\n")
                for host in unresolved:
                    f.write(f"# {host}\n")
        print(f"[+] Results written to {output_file} (TXT format, nmap-friendly)")


def beep():
    """Cross-platform beep/sound."""
    try:
        # Windows
        if sys.platform == "win32":
            import winsound

            winsound.MessageBeep()
        else:
            # Unix/macOS: ASCII bell char
            print("\a", end="", flush=True)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Resolve hostnames/URLs to IP addresses."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f", "--file", help="Input text file containing list of URLs/hostnames"
    )
    group.add_argument(
        "-u", "--urls", nargs="+", help="List of URLs/hostnames to resolve"
    )

    parser.add_argument(
        "-o", "--output", help="Output file to save results (txt or csv)"
    )
    parser.add_argument(
        "-s", "--sound", action="store_true", help="Make a sound when finished"
    )

    args = parser.parse_args()

    # Collect URLs
    urls = []
    if args.file:
        urls = read_urls_from_file(args.file)
    elif args.urls:
        urls = args.urls

    if not urls:
        print("[!] No hostnames provided.")
        return

    resolved = {}
    unresolved = []

    for hostname in urls:
        ip = resolve_hostname(hostname)
        if ip:
            resolved[hostname] = ip
        else:
            unresolved.append(hostname)

    print("\n=== Resolution Results ===")

    if resolved:
        print("\n[Resolved]")
        for host, ip in resolved.items():
            print(f"{host} → {ip}")

    if unresolved:
        print("\n[Unresolved]")
        for host in unresolved:
            print(f"{host}")

    # Save to output file if specified
    if args.output:
        save_results(args.output, resolved, unresolved)

    if args.sound:
        beep()

    print("\nDone.")


if __name__ == "__main__":
    main()
