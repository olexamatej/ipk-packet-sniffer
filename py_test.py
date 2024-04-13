from scapy.all import *

# Create IPv6 header
ip = IPv6(dst="::1")

# Create ICMPv6 Echo Request
icmp = ICMPv6EchoRequest()

# Combine headers
packet = ip / icmp

# Send the packet
send(packet)
