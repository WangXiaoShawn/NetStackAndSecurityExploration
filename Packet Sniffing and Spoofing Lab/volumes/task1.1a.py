#!/user/bin/env/ python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()
    
pkt=sniff(iface='br-6a3cad35a040',filter='icmp',prn=print_pkt)

