#!/user/bin/env/ python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()
    
pkt=sniff(iface='br-6a3cad35a040',filter='net 190.0.1.0/24',prn=print_pkt,count=1)

