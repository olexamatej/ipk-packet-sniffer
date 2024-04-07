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
        private:
            Connection conn;
    };

#endif