#!/user/bin/env/ python3
from scapy.all import *

ip= IP()
ip.src= "1.2.3.4"# set a arbitary source IP
ip.dst="10.9.0.5"# set the destination to HostA
icmp=ICMP()
pkt=ip/icmp
send(pkt)



