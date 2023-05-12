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

# Create the interface tun 
tun = os.open("/dev/net/tun", os.O_RDWR) 
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI) 
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr) 
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00") 
print("Interface Name: {}".format(ifname))

# bind a IP address and up the tun
os.system("ip addr add 192.168.53.1/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

# set route table:
#os.system("ip route add 192.168.53.99 dev {} via 192.168.53.1".format(ifname))
# Create the socket and listen to port 9090 
IP_A = "0.0.0.0" 
PORT = 9090 
recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
recv_socket.bind((IP_A, PORT))

# Create UDP socket
CLIENT_IP = '10.9.0.5' 
CLIENT_PORT = 9090
send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True: 
    ready, _, _ = select.select([recv_socket, tun], [], []) 
    for fd in ready: 
        if fd is recv_socket: 
            data, (ip, port) = recv_socket.recvfrom(2048)
            pkt = IP(data) 
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun,data)
        if fd is tun:
            packet = os.read(tun, 2048) 
            pkt = IP(packet) 
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            send_socket.sendto(packet, (CLIENT_IP, CLIENT_PORT))
