#ifndef SNIFFER_H
#define SNIFFER_H
#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "connection.h"


class Sniffer{
    public:
        int sniff(Connection conn);
        
    };

#endif