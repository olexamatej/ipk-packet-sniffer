#include "connection.h"

Connection::Connection(){
    this->port_dst = 0;
    this->port_src = 0;
    this->tcp = false;
    this->udp = false;
    this->num_packets = 1;
    this->arp = false;
    this->icmp4 = false;
    this->icmp6 = false;
    this->igmp = false;
    this->mld = false;
    this->ndp = false;
}

void Connection::print_connection(){
    std::cout << "Interface: " << this->interface << std::endl;
    std::cout << "TCP: " << this->tcp << std::endl;
    std::cout << "UDP: " << this->udp << std::endl;
    std::cout << "Number of packets: " << this->num_packets << std::endl;
    std::cout << "ARP: " << this->arp << std::endl;
    std::cout << "ICMP4: " << this->icmp4 << std::endl;
    std::cout << "ICMP6: " << this->icmp6 << std::endl;
    std::cout << "IGMP: " << this->igmp << std::endl;
    std::cout << "MLD: " << this->mld << std::endl;
}