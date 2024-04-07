#ifndef CONNECTION_H
#define CONNECTION_H
#include <string>
#include <iostream>

class Connection{
    public:
        Connection();
        void print_connection();
        std::string interface;
        int port;
        bool tcp;
        bool udp;
        int num_packets;
        bool arp;
        bool icmp4;
        bool icmp6;
        bool igmp;
        bool mld;
};

#endif