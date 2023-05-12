#!/usr/bin/env python3

import fcntl #fcntl and struct are used to manipulate file descriptors and control structures
import struct #os is used to interact with the operating system
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca #This line defines the constant TUNSETIFF, 
#which is an ioctl command used to set the name of a TUN/TAP network interface.
IFF_TUN   = 0x0001 #IFF_TUN indicates that the interface should be a TUN interface
IFF_TAP   = 0x0002 #IFF_TUN indicates that the interface should be a TUN interface
IFF_NO_PI = 0x1000 #IFF_NO_PI indicates that packet information headers should not be included.
# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
#This line opens the /dev/net/tun device file with read and write permissions 
#and returns a file descriptor for it. This file descriptor is used to interact with the TUN/TAP interface.
ifr = struct.pack('16sH', b'Xiao%d', IFF_TUN | IFF_NO_PI)
#This line creates a packed struct object containing the name and flags for the TUN/TAP interface. 
#The 16s format string specifies a string of 16 bytes, and the H format string specifies an unsigned short integer. 
#The b'Xiao%d' byte string is used as a format string to create the name of the interface,
#with %d used as a placeholder for an integer value. The IFF_TUN | IFF_NO_PI expression is used to combine the flags for the interface.
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)
#This line sends an ioctl command to the TUN/TAP device file using the fcntl.ioctl function. 
#The TUNSETIFF command sets the name of the interface to the packed ifr structure. 
#The ifname_bytes variable contains the bytes representing the name of the interface.

# Get the interface name
#This line decodes the bytes representing the name of the interface as a UTF-8 string a
#nd trims any null bytes at the end. The resulting string is stored in the ifname variable.
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))#First, we need to assign an IP address to it
os.system("ip link set dev {} up".format(ifname))#Second, we need to bring up the interface,
#because the interface is still in the down state
while True:
# Get a packet from the tun interface
    packet = os.read(tun, 2048)# buffer 2048
    if packet:
        pkt = IP(packet)
        print(pkt.summary())
    if ICMP in pkt:
        newip = IP(src=pkt[IP].dst,dst=pkt[IP].src,ihl=pkt[IP].ihl)
        newip.ttl = 99
        newicmp = ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)
        if pkt.haslayer(Raw):
            data="Huge Dick is coming"
            newpkt= newip/newicmp/data
        else:
            newpkt= mewip/newicmp
        os.write(tun,bytes(newpkt))

