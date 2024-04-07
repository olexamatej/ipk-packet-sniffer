#include "arg_parser.h"


int parse_arg(int argc, char *argv[]){
    int opt;
    std::string interface;
    int port = 0;
    bool tcp = false;
    bool udp = false;
    int num_packets = 1;
    bool arp = false;
    bool icmp4 = false;
    bool icmp6 = false;
    bool igmp = false;
    bool mld = false;

    const option long_options[] = {
        {"interface", required_argument, NULL, 'i'},
        {"port", required_argument, NULL, 'p'},
        {"tcp", no_argument, NULL, 't'},
        {"udp", no_argument, NULL, 'u'},
        {"arp", no_argument, NULL, 0},
        {"icmp4", no_argument, NULL, 0},
        {"icmp6", no_argument, NULL, 0},
        {"igmp", no_argument, NULL, 0},
        {"mld", no_argument, NULL, 0},
        {NULL, 0, NULL, 0}
    };
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "i:p:tun:", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 't':
            tcp = true;
            break;
        case 'u':
            udp = true;
            break;
        case 'n':
            num_packets = atoi(optarg);
            break;
        case 0:
            if (strcmp(long_options[option_index].name, "arp") == 0) {
                arp = true;
            } else if (strcmp(long_options[option_index].name, "icmp4") == 0) {
                icmp4 = true;
            } else if (strcmp(long_options[option_index].name, "icmp6") == 0) {
                icmp6 = true;
            } else if (strcmp(long_options[option_index].name, "igmp") == 0) {
                igmp = true;
            } else if (strcmp(long_options[option_index].name, "mld") == 0) {
                mld = true;
            }
            break;
        default: 
            fprintf(stderr, "Usage: %s -i interface [-p port] [-t] [-u]\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (interface.empty()) {
        std::cerr << "Interface not specified. Usage: " << argv[0] << " -i interface [-p port] [-t] [-u]" << std::endl;
        exit(EXIT_FAILURE);
    }
    if (port != 0 && !(tcp || udp)) {
        fprintf(stderr, "If port is specified, either -t or -u must be specified.\n");
        exit(EXIT_FAILURE);
    }

    std::cout << "Interface: " << interface << std::endl;
    if (port != 0) {
        std::cout << "Port: " << port << std::endl;
    }
    if (tcp) {
        std::cout << "TCP: true\n";
    }
    if (udp) {
        std::cout << "UDP: true\n";
    }
    std::cout << "Number of packets: " << num_packets << "\n";
    if (arp) {
        std::cout << "ARP: true\n";
    }
    if (icmp4) {
        std::cout << "ICMPv4: true\n";
    }
    if (icmp6) {
        std::cout << "ICMPv6: true\n";
    }
    if (igmp) {
        std::cout << "IGMP: true\n";
    }
    if (mld) {
        std::cout << "MLD: true\n";
    }

}