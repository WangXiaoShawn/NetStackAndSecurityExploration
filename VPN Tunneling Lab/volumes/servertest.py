#!/usr/bin/env python3 
import fcntl 
import struct 
import os 
import time 
from scapy.all import * 
TUNSETIFF = 0x400454ca 
IFF_TUN = 0x0001 
IFF_TAP = 0x0002 
IFF_NO_PI = 0x1000 
SERVER_IP = '10.9.0.11' 
SERVER_PORT = 9090 
# Create the tun interface 
tun = os.open("/dev/net/tun", os.O_RDWR) 
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI) 
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr) 
# Get the interface name 
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00") 
print("Interface Name: {}".format(ifname)) 
# Assign IP to interface and turn on the interface 
os.system("ip addr add 192.168.53.1/24 dev {}".format(ifname))
#os.system("ip addr add 192.168.53.1/24 dev {}".format(ifname))

os.system("ip link set dev {} up".format(ifname)) 
# Create the socket and listen to port 9090 
IP_A = "0.0.0.0" 
PORT = 9090 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
sock.bind((IP_A, PORT)) 
while True: 
    data, (ip, port) = sock.recvfrom(2048) 
    print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
    pkt = IP(data) 
    print(" Inside: {} --> {}".format(pkt.src, pkt.dst)) # send the packet 
    os.write(tun,data)
