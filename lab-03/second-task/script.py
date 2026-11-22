from scapy.utils import rdpcap
from scapy.packet import Raw
import string

PCAP_FILE = "capture-6.pcap"
FRAME_290 = 290
FRAME_479 = 479
KNOWN_PLAINTEXT_FILE = "expense-form.txt"

packets = rdpcap(PCAP_FILE)

def get_ciphertext(frame_number):
    pkt = packets[frame_number - 1]
    if not pkt.haslayer(Raw):
        raise ValueError(f"Frame {frame_number} non ha un layer Raw (payload non disponibile)")
    raw = bytes(pkt[Raw].load)

    return raw[8:]

c1 = get_ciphertext(FRAME_290)
c2 = get_ciphertext(FRAME_479)

print(f"Frame {FRAME_290}: {len(c1)} byte cifrati")
print(f"Frame {FRAME_479}: {len(c2)} byte cifrati")

with open(KNOWN_PLAINTEXT_FILE, "rb") as f:
    known = f.read()

printable = set(bytes(string.printable, "ascii"))

def is_mostly_printable(data, threshold=0.9):
    if not data:
        return False
    good = sum(1 for b in data if b in printable)
    return good / len(data) >= threshold

for offset in range(0, len(c1) - len(known) + 1):
    window = c1[offset:offset + len(known)]
    keystream = bytes(a ^ b for a, b in zip(window, known))

    end = min(offset + len(known), len(c2))
    if end <= offset:
        continue
    c2_window = c2[offset:end]
    ks_window = keystream[:end - offset]
    candidate = bytes(a ^ b for a, b in zip(c2_window, ks_window))

    if is_mostly_printable(candidate):
        print(f"offset={offset}: {candidate!r}")