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

# Surpress scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from random import randint
import systemGlobals as state
import threading
import time
import os
import sys
import socket
import fcntl

import signal
import sys

# Global variables/states
# -----
# clients - a dictionary mapping IP addresses to MAC addresses
# openPorts - a dictionary mapping IP addresses to a list of their open ports
# macTable - an integer that corresponds to the number of recieved CAM table entries

# Visible clients - Key is IP, Value is MAC Addr.
clients = state.clientList
# Clients in the internal network behind .35 - Key is IP, value is MAC Addr.
internalClients = state.internalClientList
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
# Returns a fake MAC Address based on a given IP in the internal network
def getInternalMAC(IP):
  return "12:67:4f:a2:6d:" + ("%02x" % int(getLastOctet(IP)))
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
    time.sleep(10)

# Increments the knock step as the user sends the correct port knock pattern
def knockAnswer(pkt):
  ports = [951,951,4826,443,100,21]
  if (pkt[IP].src == '10.5.0.4' or 
        pkt[TCP].dport not in ports or 
        state.knockSequence >= len(ports)):
    return
  if pkt[TCP].dport == ports[state.knockSequence]:
    state.knockSequence += 1
  else:
    state.knockSequence = 0  

  if state.knockSequence >= len(ports):
    openPorts['10.5.0.6'].append(25)
    gwTrafficDaemon.start()

# Simulated Traffic from clients behind 10.5.0.35 to local clients.
#  Every fifth packet will be a SYN packet from 10.5.0.6:25 > 10.1.8.6:25,
#  and all other packets are random and of little interest.
def gwTraffic():
  srcs = ['10.5.0.6','10.5.0.4']
  dsts = ['10.1.8.2','10.1.8.22']
  pktInterval = 0
  gwMAC = clients['10.5.0.35']
  while 1:
    if pktInterval != 4:
      # Generate some mac/port combination
      randomPort = randint(1,65535 - 1)
      rndSrc = randint(0,1)
      rndDst = randint(0,1) 
      source = srcs[rndSrc]
      dest = dsts[rndDst]
      ip = IP(src = source, dst = dest)
      ether = Ether(src = clients[source], dst = gwMAC)
      tcp = TCP(sport = randomPort, dport = randomPort + 1, flags = 0x002, window = 2048, seq = 0)
    
    elif state.ftpIsAlive == False:
      # Send a TCP packet from 10.5.0.6:21 to 10.1.8.6:21 (FTP)
      source = '10.5.0.6'
      dest = '10.1.8.6'
      ip = IP(src = source, dst = dest)
      ether = Ether(src = clients[source], dst = gwMAC)
      tcp = TCP(sport = 21, dport = 21, flags = 0x002, window = 2048, seq = 0)
    
    # Send packet
    SYN = ether/ip/tcp
    os.write(tun, SYN.build())
    # Response
    processPacket(SYN)
    # increment pktInterval mod 5 and sleep for 5 seconds
    pktInterval = (pktInterval + 1) % 5
    time.sleep(5)


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
# void processPacket(packet p) 
#   Processes the input packet, using the below functions to generate a response and
#   write to the TUN/TAP interface.
# 
# Packet Replies
# -----
# packet arpIsAt(packet p) 
#   Generates an ARP Is-At response to an ARP Who-Has request
# packet tcpSA(packet p)   
#   Generates a TCP SYN-ACK response to a TCP SYN request (indicative of open/unfiltered port)
# packet tcpRA(packet p)   
#   Generates a TCP RES-ACK response to a TCP SYN request (indicative of closed port)
# packet tcpA(packet p)    
#   Generates a TCP ACK response to a TCP SYN-ACK (Completed TCP handshake)
# packet tcpFA(packet p)   
#   Generates a TCP FIN-ACK response to close a TCP connection
# 
# smtpInit(packet p) 
#   Initializes an SMTP session and sends a standard introduction payload
# smtpResp(packet p) 
#   Response for a 'EHLO'/'HELO' information query
# 
# ftpInit(packet p) 
#   Initializes a FTP session and sends a standard introduction payload
# ftpResp(packet p 
#   Response for standard FTP queries (USER, PASS, LIST, RETR)

# Recieve and process incoming packets 
def processPacket(pkt):

  if pkt.haslayer(ARP):
    # Globally set ARP table if the router is in hub mode
    if pkt[ARP].op == 2 and pkt[ARP].psrc in clients: 
      clients[pkt[ARP].psrc] = pkt[ARP].hwsrc
    
    if pkt[ARP].pdst in clients:
      o4 = getLastOctet(pkt[ARP].pdst)
      globals()['dot'+o4](pkt) # Call the dot[last_octet] function
    elif pkt[ARP].pdst in internalClients:
      o4 = getLastOctet(pkt[ARP].pdst)
      globals()['internalDot'+o4](pkt) # Call the internalDot[last_octet] function

  elif (pkt.haslayer(ICMP) and
      pkt[ICMP].type == 8): # ICMP echo-request
    if pkt[IP].dst in clients:
      o4 = getLastOctet(pkt[IP].dst)
      globals()['dot'+o4](pkt) # Call the dot[last_octet] function
    elif pkt[IP].dst in internalClients:
      o4 = getLastOctet(pkt[IP].dst)
      globals()['internalDot'+o4](pkt) # Call the internalDot[last_octet] function

  elif (pkt.haslayer(TCP)):
    if pkt[IP].dst in clients:
      o4 = getLastOctet(pkt[IP].dst)
      globals()['dot'+o4](pkt)
    elif pkt[IP].dst in internalClients:
      o4 = getLastOctet(pkt[IP].dst)
      globals()['internalDot'+o4](pkt) # Call the internalDot[last_octet] function
  
  elif (pkt.haslayer(Ether) and 
      not pkt.haslayer(ICMP) and 
      state.macTable < 1024):
    state.macTable += 1 # Add an "entry" to the "MAC table"
    if state.macTable > 1023:
      knockDaemon.start()
      state.hubMode = True

# Generate a proper ARP who-has reply (is-at)
def arpIsAt(pkt):
  if pkt[ARP].pdst in clients:
    fake_src_mac = clients[pkt[ARP].pdst]
  elif pkt[ARP].pdst in internalClients:
    fake_src_mac = internalClients[pkt[ARP].pdst]
  ether = Ether(dst=pkt.hwsrc, src=fake_src_mac)
  arp = ARP(op="is-at", psrc=pkt.pdst, pdst="10.5.0.1", hwsrc=fake_src_mac, hwdst=pkt.hwsrc)
  rpkt = ether/arp
  return rpkt

# Generates an ICMP echo reply
def icmpEchoReply(pkt):
  rpkt = pkt.copy()
  swapSrcAndDst(rpkt, Ether)
  swapSrcAndDst(rpkt, IP)
  rpkt[ICMP].type = 'echo-reply'
  rpkt[ICMP].chksum = None # Recalculate checksum
  rpkt[IP].chksum = None
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
  rpkt[TCP].seq = 0
  rpkt[TCP].ack = pkt[TCP].seq
  rpkt[IP].chksum = None # Recalculate the checksums
  rpkt[TCP].chksum = None
  rpkt[TCP].sport, rpkt[TCP].dport = rpkt[TCP].dport, rpkt[TCP].sport
  return rpkt

# Generates a Finalize-Ack response to a Finalize request, to complete a TCP disconnect
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

# Generates an Ack response to a Syn-Ack request, completing a three-way handshake
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

# Generates a PSH-ACK response to a successful handshake, with an SMTP standard payload
def smtpInit(pkt):
  ether = Ether(dst = pkt[Ether].src, src = pkt[Ether].dst)
  ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
  tcp = TCP(flags='PA',seq=pkt[TCP].ack,ack=pkt[TCP].seq,sport = pkt[TCP].dport, dport = pkt[TCP].sport)
  rpkt = ether/ip/tcp/'220-smtp02.mail.example.org ESMTP\r\n'
  return rpkt

# Generates a PSH-ACK response to an SMTP information query (ie, EHLO or HELO)
def smtpResp(pkt):
  ether = Ether(dst = pkt[Ether].src, src = pkt[Ether].dst)
  ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
  tcp = TCP(flags='PA',seq=pkt[TCP].ack,ack=pkt[TCP].seq + len(pkt[Raw].load),sport = pkt[TCP].dport, dport = pkt[TCP].sport)
 
  SMTPargs = pkt[Raw].load.split(" ")
  SMTPargs = [w.strip('\r\n') for w in SMTPargs]

  if not 0 < len(SMTPargs) < 2:
    load = '501-Invalid Command\r\n'
  

  elif ("EHLO" == SMTPargs[0] 
      or "HELO" == SMTPargs[0]):
    load = '250-Welcome - smtp02 - Secondary SMTP Server\r\n250 Primary server at 10.1.8.6\r\n'
  else:
    load = '501-Invalid Command\r\n'

  rpkt = ether/ip/tcp/load
  return rpkt

# Generates a PSH-ACK response to a successful handshake, with an FTP standard payload
def ftpInit(pkt):
  ether = Ether(dst = pkt[Ether].src, src = pkt[Ether].dst)
  ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
  tcp = TCP(flags='PA',seq=pkt[TCP].ack,ack=pkt[TCP].seq,sport = pkt[TCP].dport, dport = pkt[TCP].sport)
  rpkt = ether/ip/tcp/'220-QTCP ftp01.example.org\r\n'
  return rpkt

# Generates a PSH-ACK response based on a given FTP command
def ftpResp(pkt):
  ether = Ether(dst = pkt[Ether].src, src = pkt[Ether].dst)
  ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
  tcp = TCP(flags='PA',seq=pkt[TCP].ack,ack=pkt[TCP].seq + len(pkt[Raw]),sport = pkt[TCP].dport, dport = pkt[TCP].sport)

  FTPargs = pkt[Raw].load.split(" ")
  FTPargs = [w.strip('\r\n') for w in FTPargs]

  # Detect command and reply appropriately
  if not 0 < len(FTPargs) < 3:
    load = '501-Invalid Command\r\n'
  
  # If USER is sent as the first argument, parse the second as the username.
  elif ("USER" == FTPargs[0] and 
      len(FTPargs) == 2 and 
      not state.ftpUserEntered):

    state.ftpUserEntered = True
    state.ftpUser = FTPargs[1]
    load = "331-Enter Password.\r\n"
  
  # If PASS is sent as the first argument, parse the second as the password.
  #  Do nothing if USER is not yet parsed.
  #  Authenticate iff both USER, PASS are set correctly as (admin, admin)
  elif ("PASS" == FTPargs[0] and 
      state.ftpUserEntered and 
      not state.ftpPassEntered):

    if (state.ftpUser == "admin" and 
        len(FTPargs) == 2 and 
        FTPargs[1] == "admin"): 
      state.ftpPassEntered = True
      load = "230-Admin logged on.\r\n"
    else:
      state.ftpUser = None
      state.ftpUserEntered = False
      load = "430-Invalid Username or Password.\r\n"
  
  # If LIST is sent as the only argument, then return a payload listing the target file.
  #  Do nothing if not authenticated.
  elif ("LIST" == FTPargs[0] and 
      len(FTPargs) == 1):

    if state.ftpPassEntered == False:
      load = "530-User not logged in.\r\n"
    else:
      load = "250-topSecret.txt\r\n"
  
  # If RETR is sent as the first argument, then parse the second as the source filename.
  #  Do nothing if the user is not authenticated.
  #  Do nothing if the filename is invalid.
  elif ("RETR" == FTPargs[0] and 
      len(FTPargs) == 2):

    if state.ftpPassEntered == False:
      load = "530-User not logged in.\r\n"
    else:
      if FTPargs[1] == "topSecret.txt":
        #First send a confirmation packet
        confLoad = "150-Retreiving file topSecret.txt\r\n"
        os.write(tun, (ether/ip/tcp/confLoad).build())
        load = """FTP Data (W WARNING THIS IS WARNING\r\n
          V AP-VERSION 1.0\r\n
          W Congratulations on completing scapyHunt. 
          Hash this payload with SHA1 to confirm that you've won.\r\n"""
      else: 
        load = "550-File Not Found.\r\n"
  
  else:
    load = '501-Invalid Command\r\n'


  rpkt = ether/ip/tcp/load
  return rpkt

# Destination Specific Packet Processing
# -----
# Each dot[last_octet] function has a set of packet processing rules specific to each 'Client'
#  dot4  - Standard client
#  dot6  - Secondary SMTP server (port-knocking target)
#  dot35 - Gateway to internal network with redirection based on destination MAC
#  internalDot2 - Standard internal client
#  internalDot6 - Internal FTP server and target
#  internalDot22 - Standard internal client

def dot4(pkt):
  rpkt = None

  # ICMP echo handling
  if (pkt.haslayer(ICMP) and
      pkt[ICMP].type == 8):
    rpkt = icmpEchoReply(pkt)

  # ARP handling
  if (pkt.haslayer(ARP) and 
      pkt[ARP].op == 1):
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

  # ICMP echo handling
  if (pkt.haslayer(ICMP) and
      pkt[ICMP].type == 8):
    rpkt = icmpEchoReply(pkt)

  # ARP handling
  if (pkt.haslayer(ARP) and 
      pkt[ARP].op == 1):
    rpkt = arpIsAt(pkt)
    
  # TCP handling
  elif (pkt.haslayer(TCP)):
    if (state.knockSequence < 6):
      if (pkt[TCP].dport in ports and 
          pkt[TCP].flags == 0x002):
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
          if (pkt.haslayer(Raw)):
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

  # ICMP echo handling
  if (pkt.haslayer(ICMP) and
      pkt[ICMP].type == 8):
    rpkt = icmpEchoReply(pkt)

  # ARP handling
  if (pkt.haslayer(ARP) and 
      pkt[ARP].op == 1):
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
  
def internalDot2(pkt):
  rpkt = None

  # ICMP echo handling
  if (pkt.haslayer(ICMP) and
      pkt[ICMP].type == 8):
    rpkt = icmpEchoReply(pkt)

  # ARP handling
  if (pkt.haslayer(ARP) and 
      pkt[ARP].op == 1):
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

def internalDot6(pkt):
 
  # NO echo handling- configured to ignore ICMP echo

  rpkt = None
  # ARP handling
  if (pkt.haslayer(ARP)):
    if pkt[ARP].op == 1:
      rpkt = arpIsAt(pkt)
 
  # Immediately ignore any packets not from the supposed .4 and .6 clients
  elif pkt.haslayer(Ether) and pkt[Ether].src not in [clients['10.5.0.6'],clients['10.5.0.4']]:
    return
 
 # TCP handling
  elif (pkt.haslayer(TCP)):
    if (pkt[TCP].dport in openPorts[pkt[IP].dst]):
      if (pkt[TCP].flags == 0x002): # SYN
        rpkt = tcpSA(pkt)
      
      # Handling of FTP Traffic
      if(pkt[TCP].dport == 21):
        if (pkt[TCP].flags == 0x011): # FIN-ACK
          rpkt = tcpA(pkt)
          state.ftpIsAlive = False
          state.ftpUserEntered = False
          state.ftpPassEntered = False
        elif (pkt[TCP].flags == 0x010): # ACK
          if (state.ftpIsAlive == False): 
            state.ftpIsAlive = True
            rpkt = ftpInit(pkt)
        elif (pkt[TCP].flags == 0x018): # PSH-ACK
          if pkt.haslayer(Raw):
            rpkt = ftpResp(pkt)
    
      else:
        rpkt = tcpRA(pkt)
 
  if (rpkt == None):
    return
  
  os.write(tun,rpkt.build())

def internalDot22(pkt):

  # ICMP echo handling
  if (pkt.haslayer(ICMP) and
      pkt[ICMP].type == 8):
    rpkt = icmpEchoReply(pkt)

  rpkt = None
  # ARP handling
  if (pkt.haslayer(ARP) and 
      pkt[ARP].op == 1):
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

subprocess.check_call("ifconfig %s down" % ifname, shell=True)
subprocess.check_call("ifconfig %s hw ether 12:67:7e:b7:6d:c8" % ifname, shell=True)
subprocess.check_call("ifconfig %s 10.5.0.1 netmask 255.255.255.0 broadcast 10.5.0.255 up" % ifname, shell=True)
subprocess.check_call("route add -net 10.1.8.0 netmask 255.255.255.0 gw 10.5.0.35 dev %s" % ifname, shell=True)

# Defaults and Main Loop
# -----
# Main loop processes packets by reading directly from the TUN/TAP interface and transforming
#  into scapy packets 

# Initial entries in the client list
clients['10.5.0.4'] = getMAC('10.5.0.4')
clients['10.5.0.6'] = getMAC('10.5.0.6')
clients['10.5.0.35'] = getMAC('10.5.0.35')
# Initial entries in the internal network's client list
internalClients['10.1.8.6'] = getInternalMAC('10.1.8.6')
internalClients['10.1.8.22'] = getInternalMAC('10.1.8.22')
internalClients['10.1.8.2'] = getInternalMAC('10.1.8.2')
# Initial ports in each client's open port list
openPorts['10.5.0.4'] = [20,21,22,80,443]
openPorts['10.5.0.6'] = [80,22] 
openPorts['10.5.0.35'] = [20,21,22,25,80,443,8080]
openPorts['10.1.8.6'] = [21, 25]
openPorts['10.1.8.2'] = [20, 80, 443]
openPorts['10.1.8.22'] = [20, 22, 80, 443]

print("The game is now running- tap0 interface allocated.\nEnding the process will deallocate this interface and release all state.")

def signal_handler(signal,frame):
  print("Exiting game and deallocating the tap0 interface.")
  sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

#  Main loop, reads and processes packets
while 1:
  binary_packet = os.read(tun, 2048)   # get packet routed to our "network"
  packet = Ether(binary_packet)        # Scapy parses byte string into its packet object
  processPacket(packet)
