import json
import socket
from pathlib import Path

def ip_from_u32_le(val):
    return socket.inet_ntoa(val.to_bytes(4, 'little'))

def main():
    path = Path("map.json")
    if not path.exists():
        print("❌ File 'map.json' non trovato.")
        return

    with open(path) as f:
        data = json.load(f)

    print("\n📊 DNS RTT Results\n")
    found = False
    for entry in data:
        try:
            key = entry["formatted"]["key"]
            value = entry["formatted"]["value"]
        except KeyError:
            continue  # skip if not formatted

        ip_version = key.get("ip_version", "?")
        dns_id = key.get("dns_id", "?")
        rtt_ns = value

        if ip_version == 4:
            ip = ip_from_u32_le(key["src_ip4"])
        elif ip_version == 6:
            ip = ":".join(f"{b:02x}" for b in key["src_ip6"])
        else:
            ip = "?"

        print(f"- IP: {ip:<39} | ID: {dns_id:<5} | RTT: {rtt_ns / 1e6:.3f} ms")
        found = True

    if not found:
        print("⚠️  Nessun dato 'formatted' trovato in map.json.")

if __name__ == "__main__":
    main()
