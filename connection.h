#ifndef CONNECTION_H
#define CONNECTION_H
#include <string>
#include <iostream>

// Connection class, used for storing connection parameters
class Connection{
    public:
        Connection();
        void print_connection();
        std::string interface;
        bool tcp;
        bool udp;
        int num_packets;
        bool arp;
        bool icmp4;
        bool icmp6;
        bool igmp;
        bool mld;
        bool ndp;
        int port_dst;
        int port_src;
};

#endif