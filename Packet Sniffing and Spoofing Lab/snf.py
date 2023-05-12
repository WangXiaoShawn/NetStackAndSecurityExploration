#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()

pkt=sniff(iface="br-ec3907382b6b",filter='icmp',prn=print_pkt)
