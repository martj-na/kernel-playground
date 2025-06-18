import json

def bucket_ns_to_ms(index):
    """Converte il bucket log2 in un intervallo approssimato di latenza in ms"""
    low = 1 << index
    high = (1 << (index + 1)) - 1
    return low / 1e6, high / 1e6

with open("hist.json") as f:
    data = json.load(f)

print("\n📊 DNS RTT Histogram (log2 scale)\n")
for entry in data:
    idx = int(entry["key"][0], 0)
    count = int(entry["value"][0], 0)
    low, high = bucket_ns_to_ms(idx)
    print(f"{low:.3f} ms - {high:.3f} ms : {count} packet(s)")
