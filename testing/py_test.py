from scapy.all import *

# UDP and SRC port
# ether = Ether(dst="ff:ff:ff:ff:ff:ff")
# ip = IP(dst="127.0.0.1")
# udp = UDP(sport=1234, dport=4567)
# packet = ether / ip / udp
# sendp(packet)

# TCP and DSTPORT
# ether = Ether(dst="ff:ff:ff:ff:ff:ff")
# ip = IP(dst="127.0.0.1")
# tcp = TCP(dport=4567)
# packet = ether / ip / tcp
# sendp(packet)


# mld
# ip6 = IPv6(dst="ff02::1")
# mld = ICMPv6MLQuery()
# packet = ip6 / mld
# send(packet)


# ndp
# ip6 = IPv6(dst="ff02::1")
# ndp_ns = ICMPv6ND_NS(tgt="2001:db8::1")
# packet = ip6 / ndp_ns
# send(packet)

# arp
# ethernet = Ether(dst="ff:ff:ff:ff:ff:ff")
# arp = ARP(pdst="192.168.1.1")
# packet = ethernet / arp
# sendp(packet)


# icmp4
# ip = IP(dst="127.0.0.1")
# icmp = ICMP()
# packet = ip / icmp
# send(packet)

# icmp6
ip = IPv6(dst="::1")
icmp = ICMPv6EchoRequest()
packet = ip / icmp
send(packet)
