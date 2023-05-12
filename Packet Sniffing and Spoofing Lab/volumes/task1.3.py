#!/user/bin/env/ python3
from scapy.all import *
icmp=ICMP();
ip=IP()
ip.dst="1.1.1.1" # dst is one of the atrribute of IP class
MaxTry=30 # The distination may not be reachable, set it to 30 to avoid infinity loop
TTL=0 
StopFlag=True
while StopFlag and TTL< MaxTry:
    TTL+=1
    ip.ttl=TTL # set the current ttl value and for each loop increase 1
    hops=sr1(ip/icmp, timeout=2,verbose=0) # hops is the return value of sr1()
    if hops is None:# if return value is none, which means we cannot get the target by this TTL
        # print the TTL then go to the next loop.
        print("Router:*** (hops={})".format(TTL))
    else:# reach the dst and break the loop
        print("Router:{}(hops={})".format(hops.src,TTL))# the return value will send my a route 
        # with it ip address, so we can use hops.src get the router ip address and print 
        if hops.src==ip.dst:
            StopFlag=False


