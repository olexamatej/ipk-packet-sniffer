#ifndef ARG_PARSER_H
#define ARG_PARSER_H
#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <getopt.h>
#include <string>
#include <cstring>
#include "connection.h"
#include "sniffer.h"



Connection parse_arg(int argc, char *argv[]);


#endif