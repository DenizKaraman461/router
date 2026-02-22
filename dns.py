import scapy.all as scapy
import os

def get_arp_table_windows():
    output = os.popen("arp -a").read()
    devices = []
    for line in output.split("\n"):
        line = line.strip()
        if "dynamic" in line:
            parts = line.split()
            if len(parts) >= 3:
                devices.append({"ip": parts[0], "mac": parts[1]})
    return devices

def dns_sniff(interface, target_ip):
    print(f"\n[*] Monitoring traffic for {target_ip}...")
    scapy.sniff(iface=interface, store=False, filter="udp port 53", prn=lambda x: process_dns(x, target_ip))

def process_dns(packet, target_ip):
    if packet.haslayer(scapy.DNSQR) and packet[scapy.IP].src == target_ip:
        query = packet[scapy.DNSQR].qname.decode("utf-8").rstrip(".")
        print(f"[+] ACCESSED SITE: {query}")

if __name__ == "__main__":
    print("\n" + "="*40)
    print("[*] DNS MONITOR")
    print("="*40)

    devices = get_arp_table_windows()
    print("ID\tIP Address")
    print("-" * 30)

    for i, dev in enumerate(devices):
        print(f"[{i}] \t{dev['ip']}")

    try:
        choice = int(input("\n[?] Select Target ID: "))
        target_ip = devices[choice]["ip"]
        interface = scapy.conf.iface.name
        dns_sniff(interface, target_ip)
    except Exception as e:
        print(f"[!] Error: {e}")