#!/usr/bin/env python3

import json
import socket
import ipaddress
from pathlib import Path

def parse_entry(entry):
    try:
        key = entry["formatted"]["key"]
        value = entry["formatted"]["value"]
    except KeyError:
        return None  # salta se manca "formatted"

    ip_version = key.get("ip_version", "?")
    dns_id = key.get("dns_id", "?")

    if ip_version == 4:
        ip_raw = key["src_ip4"]
        ip = socket.inet_ntoa(int(ip_raw).to_bytes(4, "little"))
    elif ip_version == 6:
        ip6_bytes = bytes(key["src_ip6"])
        ip = str(ipaddress.IPv6Address(ip6_bytes))
    else:
        ip = "UNKNOWN"

    return f"- IP: {ip:<39} | ID: {dns_id:<5} | Time (ns): {value}"

def main():
    path = Path("map.txt")
    if not path.exists():
        print("File 'map.txt' not found.")
        return

    with open(path) as f:
        data = json.load(f)

    print("\n📥 DNS QUERY TIMESTAMPS (from map.txt)\n")
    for entry in data:
        line = parse_entry(entry)
        if line:
            print(line)

if __name__ == "__main__":
    main()
