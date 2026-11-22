## Wireshark filters

```
eapol
```
Found: complete handshake (M1-M4) for client `Apple_30:d6:1f`, plus a retransmitted Message 3 (frame 362) and Message 4 (frame 363) later in the capture.

```
wlan.addr == 8c:85:90:30:d6:1f && wlan.fc.protected == 1
```
Isolates the vulnerable client's data frames. `wlan.ccmp.extiv` applied as column to track the PN.

- Frame 393: first data frame after reinstallation, PN reset to `0x01`
- Frame 290: PN `0x10`, before replay (known content, `expense-form.txt`)
- Frame 479: PN `0x10`, after replay (target, login request)

## Export ciphertext

```bash
tshark -r capture-6.pcap -Y "frame.number == 290" -T fields -e data.data
tshark -r capture-6.pcap -Y "frame.number == 479" -T fields -e data.data
```

## Keystream recovery

Python + scapy script (crib dragging: known plaintext slid over frame 290's ciphertext to derive the keystream, applied at the same offset to frame 479).

## Flag found

```
netsec{a2db2508e3c48b11bf6e79a8b3c741f2}
```
