#include "arg_parser.h"
#include "connection.h"

Connection parse_arg(int argc, char *argv[]){
    Connection conn;
    int opt;
  
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
            conn.interface = optarg;
            break;
        case 'p':
            conn.port = atoi(optarg);
            break;
        case 't':
            conn.tcp = true;
            break;
        case 'u':
            conn.udp = true;
            break;
        case 'n':
            conn.num_packets = atoi(optarg);
            break;
        case 0:
            if (strcmp(long_options[option_index].name, "arp") == 0) {
                conn.arp = true;
            } else if (strcmp(long_options[option_index].name, "icmp4") == 0) {
                conn.icmp4 = true;
            } else if (strcmp(long_options[option_index].name, "icmp6") == 0) {
                conn.icmp6 = true;
            } else if (strcmp(long_options[option_index].name, "igmp") == 0) {
                conn.igmp = true;
            } else if (strcmp(long_options[option_index].name, "mld") == 0) {
                conn.mld = true;
            }
            break;
        default: 
            fprintf(stderr, "Usage: %s -i interface [-p port] [-t] [-u]\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (conn.interface.empty()) {
        std::cerr << "Interface not specified. Usage: " << argv[0] << " -i interface [-p port] [-t] [-u]" << std::endl;
        exit(EXIT_FAILURE);
    }
    if (conn.port != 0 && !(conn.tcp || conn.udp)) {
        fprintf(stderr, "If port is specified, either -t or -u must be specified.\n");
        exit(EXIT_FAILURE);
    }
    return conn;
}