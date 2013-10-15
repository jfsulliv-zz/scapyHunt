**scapyHunt** - A series of Network Security puzzles and challenges designed to educate users on packet manipulation
and common network attacks. 

Creates a TUN/TAP interface for the virtual network 10.5.0/24, over which packets will be sent by the
user- either hand crafted or using a variety of tools- in order to achieve a given objective.

Uses scapy, a Python packet manipulation library.

http://www.secdev.org/projects/scapy/

-----

Recommended tools for use-

http://www.secdev.org/projects/scapy/ - Packet manipulation

https://www.wireshark.org/ - Packet sniffing

http://nmap.org/ - Network topography

http://www.monkey.org/~dugsong/dsniff/ - Collection of penetration testing tools, ie 'macof'

Note that some tools may require the user to specify the TUN/TAP interface, rather than a default interface.
