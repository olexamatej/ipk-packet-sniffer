#ifndef SNIFFER_H
#define SNIFFER_H
#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "connection.h"
#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

class Sniffer{
    public:
        Sniffer(Connection conn);        
        int sniff();
        int init_pcap();
        std::string get_filters();
        void print_mac(const u_char *packet, int start, const char *label);
        void print_hexdump(const u_char *packet, int len);
        void print_timestamp(const struct pcap_pkthdr header);
        void print_frame_length(const struct pcap_pkthdr header);
        void print_IP_port(const u_char *packet, struct ether_header *eth, const struct pcap_pkthdr &header);
        void printIPv4(const u_char *packet,const struct pcap_pkthdr &header);
        void printIPv6(const u_char *packet, const struct pcap_pkthdr &header);
        void printARP(const u_char *packet);

        private:
        Connection conn;
        pcap_t *handle;
};


#endif