## 1. Extracting EAPOL handshakes from the pcap

Convert the capture into hashcat's 22000 format (extracts every EAPOL/PMKID handshake found):

```bash
hcxpcapngtool -o hashes.22000 capture-6.pcap
```

Reading of the generated txt file:

```bash
cat hashes.22000
```

## 2. Identifying the correct network (SSID)

Field 6 (`*`-separated) contains the SSID encoded in hex. Extract the field:

```bash
awk -F'*' '{print $6}' hashes.22000
```

Decode from hex to ASCII to read the SSID in plain text:

```bash
awk -F'*' '{print $6}' hashes.22000 | while read -r h; do echo "$h" | xxd -r -p; echo; done
```

Result: 3 handshakes for `Acme-WiFi` (correct network) and 1 for `Acme_WiFi` (similar but different SSID)

## 3. Filtering only the target SSID lines

```bash
#in this way we can filter the correct SSID from the hashes.22000 file and save it to a new file called acme.22000
grep '41636d652d57694669' hashes.22000 > acme.22000
cat acme.22000 #visualizzation of the new file created
```

(`41636d652d57694669` is the hex encoding of `Acme-WiFi`)

## 4. Mask attack with hashcat

command to make an hashcat attack (lets hashcat pick the device automatically, uses the GPU):

```bash
hashcat -m 22000 -a 3 acme.22000 'Acme?d?d?d?d?d?d'
```

Recovering the cracked passphrases:

```bash
hashcat -m 22000 acme.22000 --show
```
For each handshake is associated the relative passphrase.<br/>
Result: 3/3 digests cracked, passphrases found `{Acme026512, Acme272886, Acme026512}`.

## 5. Verifying in Wireshark which handshake is valid

Filter to analyze each client MAC's traffic, in Wireshark's filter bar:

```
wlan.addr == 8c859047b860
wlan.addr == a483e749f992
wlan.addr == dca6325f9bb4
```

for the last two MAC addresses, the handshake is valid, while for the first one, the handshake is invalid.

## 6. Decrypting the traffic in Wireshark

Wireshark → Preferences → Protocols → IEEE 802.11 → Decryption keys → new key:

- **Type:** `wpa-pwd`
- **Key:** `Acme026512:Acme-WiFi`

## 7. Finding the flag in the decrypted traffic

Filter for HTTP traffic:

```
http
```

we can concentrate on the POST requests, and we can find the flag in the body of the request

