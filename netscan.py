#!/usr/bin/env python3
"""
network_mapper_html.py

Fast network mapper + port scanner with HTML reporting.
Use only on authorized networks.
"""

import argparse
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# -------------------------
# Config defaults
# -------------------------
COMMON_PORTS = [22, 23, 80, 135, 139, 143, 443, 445, 3389, 8080, 8443, 3306, 5432]
SOCKET_TIMEOUT = 1.5
MAX_THREADS = 300
BANNER_BYTES = 1024
OUTPUT_FILE = "scan_report.html"

# -------------------------
# Argument parsing
# -------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Fast network mapper + HTML report")
    parser.add_argument("--target", "-t", help="Target IP or CIDR (e.g., 10.0.0.0/24 or 8.8.8.8)", required=True)
    parser.add_argument("--ports", "-p", help="Comma-separated ports", default=None)
    parser.add_argument("--threads", type=int, default=MAX_THREADS, help="Max worker threads")
    parser.add_argument("--timeout", type=float, default=SOCKET_TIMEOUT, help="Per-connection timeout in seconds")
    parser.add_argument("--output", "-o", default=OUTPUT_FILE, help="HTML output file")
    return parser.parse_args()

# -------------------------
# Utilities
# -------------------------
def expand_targets(target_cidr):
    targets = []
    if "/" in target_cidr:
        net = ipaddress.ip_network(target_cidr, strict=False)
        targets = [str(ip) for ip in net.hosts()]
    else:
        targets = [target_cidr]
    return targets

def is_host_up(ip, probe_ports, timeout):
    # Probe a few common ports for liveness
    for port in probe_ports[:6]:
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            continue
    return False

def discover_live_hosts(targets, probe_ports, timeout, max_workers):
    live_hosts = []
    print("[+] Starting host discovery (concurrent)...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(is_host_up, ip, probe_ports, timeout): ip for ip in targets}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    print(f"  [UP] {ip}")
                    live_hosts.append(ip)
                else:
                    print(f"  [DOWN/Filtered] {ip}")
            except Exception as e:
                print(f"  [ERROR] {ip} -> {e}")
    return live_hosts

def scan_port(ip, port, timeout):
    result = {"port": port, "open": False, "banner": None}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        result["open"] = True
        try:
            data = s.recv(BANNER_BYTES)
            if data:
                result["banner"] = data.decode(errors="replace").strip()
        except Exception:
            pass
        s.close()
    except Exception:
        pass
    return result

# -------------------------
# HTML report generator
# -------------------------
def generate_html_report(results, output_file):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    html = f"<html><head><title>Network Scan Report</title></head><body>"
    html += f"<h1>Network Scan Report</h1><p>Generated: {now}</p>"
    for ip, ports in results.items():
        html += f"<h2>Host: {ip}</h2><table border='1' cellpadding='5' cellspacing='0'>"
        html += "<tr><th>Port</th><th>Status</th><th>Banner</th></tr>"
        for port_result in ports:
            color = "green" if port_result["open"] else "red"
            status = "Open" if port_result["open"] else "Closed"
            banner = port_result["banner"] if port_result["banner"] else ""
            html += f"<tr><td>{port_result['port']}</td><td style='color:{color}'>{status}</td><td>{banner}</td></tr>"
        html += "</table>"
    html += "</body></html>"

    with open(output_file, "w") as f:
        f.write(html)
    print(f"[+] HTML report saved to {output_file}")

# -------------------------
# Main scanning function
# -------------------------
def main():
    args = parse_args()
    ports = [int(p) for p in args.ports.split(",")] if args.ports else COMMON_PORTS
    targets = expand_targets(args.target)

    print(f"[+] Expanding targets: {len(targets)} IPs")

    # Discover live hosts concurrently
    live_hosts = discover_live_hosts(
        targets=targets,
        probe_ports=ports,
        timeout=args.timeout,
        max_workers=max(1, min(args.threads, 1024)),
    )

    if not live_hosts:
        print("[!] No live hosts found. Exiting.")
        return

    results = {}
    print("[+] Starting port scans on live hosts...")
    for ip in live_hosts:
        results[ip] = []
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_port = {executor.submit(scan_port, ip, port, args.timeout): port for port in ports}
            for future in as_completed(future_to_port):
                results[ip].append(future.result())

    generate_html_report(results, args.output)
    print("[+] Scan complete.")

if __name__ == "__main__":
    main()
