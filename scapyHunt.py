#! usr/bin/python

#
#  scapyHunt - A scapy-based series of puzzles designed to teach the essentials
#              of network attacks and security.
#
#  Suggested tools:
#   nMap
#   wireshark
#   dsniff (for macof)
#
#  Suggested setup:
#   Run from a virtual or physical machine, connected to by the user via SSH (with/without GUI support)
#
#        

from scapy.all import *
from random import randint
import systemGlobals as state
import threading
import time
import os
import sys
import socket
import fcntl

# Global variables/states
# -----
# clients - a dictionary mapping IP addresses to MAC addresses
# openPorts - a dictionary mapping IP addresses to a list of their open ports
# macTable - an integer that corresponds to the number of recieved CAM table entries

# Visible clients - Key is IP, Value is MAC Addr.
clients = state.clientList
# Dictionary associating each client to a list of their open ports.
openPorts = state.clientOpenPorts
# The number of entries in the CAM table (simulated) for exploiting purposes.
macTable = state.macTable


# Tools
# -----
# getLastOctet - split a given IP address and return the last octet (String)
# getMAC - generate a fake MAC address based on a given IP
# swapSrcAndDst - given a packet and layer, swaps the src and dst variables

# Returns the last octet as a string for a given IP address
def getLastOctet(IP):
  o1,o2,o3,o4 = IP.split('.')
  return o4

# Returns a fake MAC Address based on a given IP
def getMAC(IP):
  return "12:67:7e:b7:6d:" + ("%02x" % int(getLastOctet(IP)))

# About-face for given packet on a particular layer
def swapSrcAndDst(pkt,layer):
  pkt[layer].src, pkt[layer].dst = pkt[layer].dst, pkt[layer].src



# Port Knocking handling
# -----
# knockDaemon - Daemon thread that handles automated traffic from .4 to .6 to reveal knock sequence
#   Terminates on successful knock from user
# knockSequence - Main loop that will send a knock sequence from .4 to .6 on a time interval
#   Target of knockDaemon
# knockAnswer - Increments the knock step as the correct pattern is sent by the user

# Loops a specific port-knocking sequence from .4 to .6 with a pause in between runs
def knockSequence():
  ports = [951,951,4826,443,100,21]
  ip = IP(dst ='10.5.0.6',src = '10.5.0.4') 
  ether = Ether(dst = clients['10.5.0.6'], src = clients['10.5.0.4'])
  while state.knockSequence < 6:
    randomPort = randint(1,65535 - 6) # Random port number
    offset = 0
    for p in ports:
      SYN = ether/ip/TCP(sport = randomPort+offset, dport = p, flags = 0x002, window = 2048, seq = 0)
      os.write(tun, SYN.build())
      offset += 1
    dot6(SYN)
    time.sleep(10)

# Increments the knock step as the user sends the correct port knock pattern
def knockAnswer(pkt):
  ports = [951,951,4826,443,100,21]
  if (pkt[IP].src == '10.5.0.4' or 
        pkt[TCP].dport not in ports or 
        state.knockSequence >= len(ports)):
    return
  print(state.knockSequence)
  if pkt[TCP].dport == ports[state.knockSequence]:
    state.knockSequence += 1
  else:
    state.knockSequence = 0  


  if state.knockSequence >= len(ports):
    openPorts['10.5.0.6'].append(25)
    gwTrafficDaemon.start()

# Simulated Traffic
def gwTraffic():
  dsts = ["10.5.0.6","10.5.0.4"]
  macs = [getMAC("10.1.8.22"), getMAC("10.1.8.2")]
  while 1:
    # Generate some mac/port combination
    randomPort = randint(1,65535 - 1)
    rndMAC = randint(0,1)
    rndDst = randint(0,1)
    mac = macs[rndMAC]
    dest = dsts[rndDst]
    # Send packet
    ip = IP(src = '10.5.0.35', dst = dest)
    ether = Ether(src = mac, dst = clients[dest])
    SYN = ether/ip/TCP(sport = randomPort, dport = randomPort + 1, flags = 0x002, window = 2048, seq = 0)
    os.write(tun, SYN.build())
    # Sleep thread for 1-16 seconds
    time.sleep(randomPort % 16 + 1)


# Creates a daemon thread that will handle simulating traffic from .4 to .6
# Start conditions: User has performed CAM table overflow, forcing routing to hub
# Termination conditions: Port-knock sequence has been completed by user
knockDaemon = threading.Thread(group=None, target=knockSequence, name=None, args=(), kwargs={}) 
knockDaemon.daemon = True

# Creates a daemon thread that will handle simulating traffic through the .35 gateway
# (Same IP but varying MACs)
# Start conditions: User has performed CAM table overflow, forcing routing to hub
# Termination conditions: N/A
gwTrafficDaemon = threading.Thread(group=None, target=gwTraffic, name=None, args=(), kwargs={})
gwTrafficDaemon.daemon = True

# Packet Processing 
# -----
# processPacket - sends packets to the correct handling function based on destination and type
# 
# Packet Replies
# -----
# arpIsAt - generates an ARP Is-At response to an ARP Who-Has request
# tcpSA   - generates a TCP SYN-ACK response to a TCP SYN request (indicative of open/unfiltered port)
# tcpRA   - generates a TCP RES-ACK response to a TCP SYN request (indicative of closed port)
# tcpA    - generates a TCP ACK response to a TCP SYN-ACK (Completed TCP handshake)
# tcpFA   - generates a TCP FIN-ACK response to close a TCP connection

# Recieve and process incoming packets 
def processPacket(pkt):
  if pkt.haslayer(ARP):
    if pkt[ARP].pdst in clients:
      o4 = getLastOctet(pkt[ARP].pdst)
      globals()['dot'+o4](pkt) # Call the dot[last_octet] function
  elif (pkt.haslayer(TCP)): # SYN
    if pkt[IP].dst in clients:
      o4 = getLastOctet(pkt[IP].dst)
      globals()['dot'+o4](pkt)
  elif (pkt.haslayer(Ether) and state.macTable < 1024):
    state.macTable += 1 # Add an "entry" to the "MAC table"
    if state.macTable > 1023:
      knockDaemon.start()

# Generate a proper ARP who-has reply (is-at)
def arpIsAt(pkt):
  fake_src_mac = clients[pkt[ARP].pdst]
  ether = Ether(dst=pkt.hwsrc, src=fake_src_mac)
  arp = ARP(op="is-at", psrc=pkt.pdst, pdst="10.5.0.1", hwsrc=fake_src_mac, hwdst=pkt.hwsrc)
  rpkt = ether/arp
  return rpkt

# Generate a Syn-Ack response to a Syn request
def tcpSA(pkt):
  rpkt = pkt.copy()
  swapSrcAndDst(rpkt,Ether)
  swapSrcAndDst(rpkt,IP)
  rpkt[TCP].flags = 'SA'
  rpkt[TCP].seq = 0x1000
  rpkt[TCP].ack = pkt[TCP].seq + 1
  rpkt[IP].chksum = None # Recalculate the checksums
  rpkt[TCP].chksum = None
  rpkt[TCP].sport, rpkt[TCP].dport = rpkt[TCP].dport, rpkt[TCP].sport
  return rpkt

# Generates a Reset-Ack response to a Syn request, indicative of a closed port
def tcpRA(pkt):
  rpkt = pkt.copy()
  swapSrcAndDst(rpkt,Ether)
  swapSrcAndDst(rpkt,IP)
  rpkt[TCP].flags = 'RA'
  rpkt[TCP].seq = 1
  rpkt[IP].chksum = None # Recalculate the checksums
  rpkt[TCP].chksum = None
  rpkt[TCP].sport, rpkt[TCP].dport = rpkt[TCP].dport, rpkt[TCP].sport
  return rpkt

def tcpFA(pkt):
  rpkt = pkt.copy()
  swapSrcAndDst(rpkt,Ether)
  swapSrcAndDst(rpkt,IP)
  rpkt[TCP].flags = 'FA'
  rpkt[TCP].seq = pkt[TCP].ack
  rpkt[TCP].ack = pkt[TCP].seq + 1
  rpkt[IP].chksum = None # Recalculate the checksums
  rpkt[TCP].chksum = None
  rpkt[TCP].sport, rpkt[TCP].dport = rpkt[TCP].dport, rpkt[TCP].sport
  return rpkt  

def tcpA(pkt):
  rpkt = pkt.copy()
  swapSrcAndDst(rpkt,Ether)
  swapSrcAndDst(rpkt,IP)
  rpkt[TCP].flags = 'A'
  rpkt[TCP].seq = pkt[TCP].ack
  if (pkt.haslayer(Raw)):
    rpkt[TCP].ack = pkt[TCP].seq + len(pkt[Raw].load)
  else: 
    rpkt[TCP].ack = pkt[TCP].seq + 1
  rpkt[IP].chksum = None # Recalculate the checksums
  rpkt[TCP].chksum = None
  rpkt[TCP].sport, rpkt[TCP].dport = rpkt[TCP].dport, rpkt[TCP].sport
  return rpkt 

def smtpInit(pkt):
  ether = Ether(dst = pkt[Ether].src, src = pkt[Ether].dst)
  ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
  tcp = TCP(flags='PA',seq=pkt[TCP].ack,ack=pkt[TCP].seq,sport = pkt[TCP].dport, dport = pkt[TCP].sport)
  rpkt = ether/ip/tcp/'220 smtp02.mail.example.org ESMTP\r\n'
  return rpkt

def smtpResp(pkt):
  ether = Ether(dst = pkt[Ether].src, src = pkt[Ether].dst)
  ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
  tcp = TCP(flags='PA',seq=pkt[TCP].ack,ack=pkt[TCP].seq,sport = pkt[TCP].dport, dport = pkt[TCP].sport)
  rpkt = ether/ip/tcp/'250 Welcome - smtp02 - Secondary SMTP Server\r\n250 Primary server at 10.1.8.6\r\n'
  return rpkt

# Destination Specific Packet Processing
# -----
# Each dot[last_octet] function has a set of packet processing rules specific to each 'Client'
# Separation of each client allows for unique behaviors

def dot4(pkt):
  rpkt = None
  # ARP handling
  if (pkt.haslayer(ARP) and pkt[ARP].op == 1):
    rpkt = arpIsAt(pkt)
    
  # TCP handling
  elif (pkt.haslayer(TCP)):
    if pkt[TCP].dport in openPorts[pkt[IP].dst]:
      if pkt[TCP].flags == 0x002: # SYN
        rpkt = tcpSA(pkt)
    else:
      rpkt = tcpRA(pkt)
  
  if (rpkt == None):
    return
  os.write(tun,rpkt.build())

def dot6(pkt):
  rpkt = None
  ports = [951,951,4826,443,100,21]
  filteredPorts = [25]
  # ARP handling
  if (pkt.haslayer(ARP) and pkt[ARP].op == 1):
    rpkt = arpIsAt(pkt)
    
  # TCP handling
  elif (pkt.haslayer(TCP)):
    if (state.knockSequence < 6):
      if (pkt[TCP].dport in ports and pkt[TCP].flags == 0x002):
        rpkt = knockAnswer(pkt)
    
    if (pkt[TCP].dport in openPorts[pkt[IP].dst]):
      if (pkt[TCP].flags == 0x002): # SYN
        rpkt = tcpSA(pkt)
      
      # Handling of SMTP Traffic
      if(pkt[TCP].dport == 25):
        if (pkt[TCP].flags == 0x011): # FIN-ACK
          rpkt = tcpA(pkt)
          state.smtpIsAlive = False
        elif (pkt[TCP].flags == 0x010): # ACK
          if (state.smtpIsAlive == False): 
            state.smtpIsAlive = True
            rpkt = smtpInit(pkt)
        elif (pkt[TCP].flags == 0x018): # PSH-ACK
          if (pkt.haslayer(Raw) and ("EHLO" in pkt[Raw].load or "HELO" in pkt[Raw].load) 
              and pkt[TCP].dport == 25):
            rpkt = smtpResp(pkt)
    
    elif pkt[TCP].dport in filteredPorts:
      return
    else:
      rpkt = tcpRA(pkt)
      
  if (rpkt == None):
    return
  os.write(tun,rpkt.build())
  
def dot35(pkt):
  rpkt = None
  # ARP handling
  if (pkt.haslayer(ARP) and pkt[ARP].op == 1):
    rpkt = arpIsAt(pkt)
    
  # TCP handling
  elif (pkt.haslayer(TCP)):
    if pkt[TCP].dport in openPorts[pkt[IP].dst]:
      if pkt[TCP].flags == 0x002: # SYN
        rpkt = tcpSA(pkt)
    else:
      rpkt = tcpRA(pkt)
  
  if (rpkt == None):
    return
  os.write(tun,rpkt.build())



# TUN/TAP Interface Setup
# -----
# Copied from Sergey's pong.py
# Credit to https://gist.github.com/glacjay/585369


# Constants needed to make a "magic" call to /dev/net/tun to create
#  a tap0 device that reads and writes raw Ethernet packets
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
TUNMODE = IFF_TAP
TUNSETOWNER = TUNSETIFF + 2

# Open TUN device file, create tap0
#
#  To open a new transient device, put "tap%d" into ioctl() below.
#  To open a persistent device, use "tap0" or the actual full name.
#
#  You can create a persistent device with "openvpn --mktun --dev tap0".
#   This device will show up on ifconfig, but will have "no link" unless  
#   it is opened by this or similar script even if you bring it up with
#   "ifconfig tap0 up". This can be confusing.
#
#  Copied from https://gist.github.com/glacjay/585369 
#   IFF_NO_PI is important! Otherwise, tap will add 4 extra bytes per packet, 
#     and this will confuse Scapy parsing.
tun = os.open("/dev/net/tun", os.O_RDWR)
ifs = ioctl(tun, TUNSETIFF, struct.pack("16sH", "tap0", TUNMODE | IFF_NO_PI))
ifname = ifs[:16].strip("\x00")  # will be tap0

# Optionally, we want tap0 be accessed by the normal user.
fcntl.ioctl(tun, TUNSETOWNER, 1000)

print "Allocated interface %s. Configuring it." % ifname

subprocess.check_call("ifconfig %s down" % ifname, shell=True)
subprocess.check_call("ifconfig %s hw ether 12:67:7e:b7:6d:c8" % ifname, shell=True)
subprocess.check_call("ifconfig %s 10.5.0.1 netmask 255.255.255.0 broadcast 10.5.0.255 up" % ifname, shell=True)



# Defaults and Main Loop
# -----
# Main loop processes packets by reading directly from the TUN/TAP interface and transforming
#  into scapy packets 

# Initial entries in the client list
clients['10.5.0.4'] = getMAC('10.5.0.4')
clients['10.5.0.6'] = getMAC('10.5.0.6')
clients['10.5.0.35'] = getMAC('10.5.0.35')
# Initial ports in each client's open port list
openPorts['10.5.0.4'] = [20,21,22,80,443]
openPorts['10.5.0.6'] = [80,22] 
openPorts['10.5.0.35'] = [20,21,22,25,80,443,8080]

#  Main loop, reads and processes packets
while 1:
  binary_packet = os.read(tun, 2048)   # get packet routed to our "network"
  packet = Ether(binary_packet)        # Scapy parses byte string into its packet object
  processPacket(packet)
