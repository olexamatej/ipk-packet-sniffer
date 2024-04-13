#ifndef SNIFFER_H
#define SNIFFER_H
#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "connection.h"
#include <string>

class Sniffer{
    public:
        Sniffer(Connection conn);        
        int sniff();
        std::string get_filters();
        void print_mac(const u_char *packet, int start, const char *label);
        void print_hexdump(const u_char *packet, int len);
        void print_timestamp(const struct pcap_pkthdr header);
        void print_frame_length(const struct pcap_pkthdr header);
        void print_IP_port(const u_char *packet, struct ether_header *eth);
        void printIPv4(const u_char *packet);
        void printIPv6(const u_char *packet);
        void printARP(const u_char *packet);

        private:
            Connection conn;
    };


#endif