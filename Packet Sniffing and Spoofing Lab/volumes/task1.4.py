#!/user/bin/env/ python3
from scapy.all import *

def spoof_pkt(pkt):
    #Inside the spoof_pkt() function, it checks if the packet is an ICMP packet with a type of 8 (ICMP Echo Request) 
    #using the ICMP in pkt and pkt[ICMP].type==8 condition.
    if ICMP in pkt and pkt[ICMP].type==8:
        print("Original Pakcet.......")
        print("Source IP:",pkt[IP].src)# print the resource IP,which send the packet
        print("Destination IP:",pkt[IP].dst)# print the desination IP, which the captured packet send to.

        # creates a new IP packet using the IP() function
        # 1. set the source IP address to the destination IP address of the original packet
        # 2. set the destination IP address to the source IP address of the original packet
        # 3.the Internet Header Length (IHL) to the value of the IHL field of the original packet 
        # 4. the Time to Live (TTL) to 90.
        ip=IP(src=pkt[IP].dst,dst=pkt[IP].src,ihl=pkt[IP].ihl,ttl=90)
        #creates a new ICMP packet using the ICMP() function 
        # 1.sets the type to 0 (ICMP Echo Reply)
        # 2.the ID and Sequence Number to the values of the ID and Sequence Number fields of the original packet.

        icmp= ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)
        #create new data packet using the Raw() function and sets the load to the data of the original packet.
        data=pkt[Raw].load
        # concatenates the IP, ICMP and data packets to create a new packet.
        newpkt=ip/icmp/data
        print("Spoofed Packet.....")
        print("Source IP:",newpkt[IP].src)
        print("Destination IP:",newpkt[IP].dst)
        # send the packet
        send(newpkt,verbose=0)


pkt=sniff(iface='br-65b8388a404e',filter='icmp and src host 10.9.0.5',prn=spoof_pkt)


