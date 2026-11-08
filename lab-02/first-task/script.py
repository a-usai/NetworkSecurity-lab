from scapy.all import rdpcap
from scapy.layers.inet import TCP
from scapy.packet import Raw
import re

packets = rdpcap("capture-6.pcap")

admin_port = None
t1, tsval1 = None, None
t0, tsval0 = None, None

for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        try:
            if 'POST /admin/login' in pkt[Raw].load.decode(errors='ignore'):
                admin_port = pkt[TCP].sport
                t1 = float(pkt.time)
                for opt in pkt[TCP].options:
                    if opt[0] == 'Timestamp':
                        tsval1 = opt[1][0]
                break
        except Exception:
            pass

if not admin_port:
    print("[-] Error: POST /admin/login not found.")
    exit(1)

for pkt in packets:
    if pkt.haslayer(TCP) and pkt[TCP].sport == admin_port and pkt[TCP].flags == 'S':
        t0 = float(pkt.time)
        for opt in pkt[TCP].options:
            if opt[0] == 'Timestamp':
                tsval0 = opt[1][0]
        break

hz_raw = (tsval1 - tsval0) / (t1 - t0)
hz = 1000 if abs(hz_raw - 1000) < 100 else (250 if abs(hz_raw - 250) < 50 else 100)
print(f"[+] Estimated clock frequency: {hz_raw:.2f} Hz -> Normalized to {hz} Hz")

traces = {}
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        try:
            payload = pkt[Raw].load.decode(errors='ignore')
            if 'X-Trace:' in payload:
                tsval_attuale = None
                for opt in pkt[TCP].options:
                    if opt[0] == 'Timestamp':
                        tsval_attuale = opt[1][0]

                if tsval_attuale:
                    tsval_atteso = tsval1 + hz * (float(pkt.time) - t1)
                    errore = abs(tsval_attuale - tsval_atteso)

                    if errore < (hz * 1.5):
                        match = re.search(r'X-Trace:\s*(\d+)-([0-9a-fA-F]{6})', payload)
                        if match:
                            traces[int(match.group(1))] = match.group(2)
        except Exception:
            pass

if len(traces) == 8:
    token = "".join([traces[i] for i in range(1, 9)])
    print(f"\n[+] Correct flag: netsec{{{token}}}")
else:
    print(f"\n[-] Error: Found only {len(traces)}/8 pieces. {traces}")