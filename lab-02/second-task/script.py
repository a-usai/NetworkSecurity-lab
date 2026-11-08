import subprocess

ja4_target = "t13d1516h2_8daaf6152771_9829734ff3cf"
tshark_path = '/Applications/Wireshark.app/Contents/MacOS/tshark'

print(f"[*] Searching for connections with JA4: {ja4_target}")

cmd = [
    tshark_path, '-r', 'capture-6.pcap',
    '-Y', f'tls.handshake.type == 1 and tls.handshake.ja4 == "{ja4_target}"',
    '-T', 'fields', '-e', 'tls.handshake.extensions_server_name'
]

try:
    # Execute tshark and parse the output
    output = subprocess.check_output(cmd, text=True).strip().split('\n')

    token = ""
    count = 0

    for sni in output:
        sni = sni.strip()
        if sni:
            first_label = sni.split('.')[0]
            token += first_label
            count += 1
            print(f"    -> Found SNI: {sni} (Extracted label: {first_label})")

    print(f"\n[+] Found {count} connections.")
    if count == 8:
        print(f"[+] Final flag: netsec{{{token}}}")
    else:
        print(f"[-] Warning: the number of fragments ({count}) is not 8.")

except Exception as e:
    print(f"[-] Error: {e}")