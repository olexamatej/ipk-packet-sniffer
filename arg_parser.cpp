#include "arg_parser.h"

Connection parse_arg(int argc, char *argv[])
{
    Connection conn;
    int opt;
    bool arg_check = false;
    // long options for getopt function
    const option long_options[] = {
        {"interface", required_argument, NULL, 'i'},
        {"tcp", no_argument, NULL, 't'},
        {"udp", no_argument, NULL, 'u'},
        {"port-destination", required_argument, NULL, 0},
        {"port-source", required_argument, NULL, 0},
        {"arp", no_argument, NULL, 0},
        {"icmp4", no_argument, NULL, 0},
        {"icmp6", no_argument, NULL, 0},
        {"igmp", no_argument, NULL, 0},
        {"mld", no_argument, NULL, 0},
        {"ndp", no_argument, NULL, 0},
        {NULL, 0, NULL, 0}};
    int option_index = 0;

    opterr = 0;
    // parse command line arguments, it checks long and short versions
    while ((opt = getopt_long(argc, argv, "i:p:tun:", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
            // interface
        case 'i':
            conn.interface = optarg;
            break;
            // port
        case 'p':
            arg_check = true;
            conn.port_dst = atoi(optarg);
            conn.port_src = atoi(optarg);
            break;
            // TCP
        case 't':
            arg_check = true;
            conn.tcp = true;
            break;
            // UDP
        case 'u':
            arg_check = true;
            conn.udp = true;
            break;
            // number of packets
        case 'n':
            arg_check = true;

            if (optarg == NULL)
            {
                std::cerr << "Error: -n requires a numeric argument\n";
                exit(EXIT_FAILURE);
            }
            conn.num_packets = atoi(optarg);
            break;
            // long options
        case 0:
            // check which long option was specified
            if (strcmp(long_options[option_index].name, "arp") == 0)
            {
                arg_check = true;
                conn.arp = true;
            }
            else if (strcmp(long_options[option_index].name, "icmp4") == 0)
            {
                arg_check = true;
                conn.icmp4 = true;
            }
            else if (strcmp(long_options[option_index].name, "icmp6") == 0)
            {
                arg_check = true;
                conn.icmp6 = true;
            }
            else if (strcmp(long_options[option_index].name, "igmp") == 0)
            {
                arg_check = true;
                conn.igmp = true;
            }
            else if (strcmp(long_options[option_index].name, "mld") == 0)
            {
                arg_check = true;
                conn.mld = true;
            }
            else if (strcmp(long_options[option_index].name, "ndp") == 0)
            {
                arg_check = true;
                conn.ndp = true;
            }
            else if (strcmp(long_options[option_index].name, "port-destination") == 0)
            {
                arg_check = true;
                conn.port_dst = atoi(optarg);
            }
            else if (strcmp(long_options[option_index].name, "port-source") == 0)
            {
                arg_check = true;
                conn.port_src = atoi(optarg);
            }

            break;
        default:
            if (optopt == 'i')
            {
                // missing obligatory argument
                printInterfaces();
                exit(EXIT_FAILURE);
            }
            else
            {
                fprintf(stderr, "Usage: %s -i interface [-p port] [-t] [-u]\n",
                        argv[0]);
                exit(EXIT_FAILURE);
            }
        }
    }
    // checks for missing obligatory arguments
    if ((conn.interface.empty() && !arg_check))
    {
        printInterfaces();

        exit(EXIT_FAILURE);
    }
    if(arg_check && conn.interface.empty()){
        fprintf(stderr, "Usage: %s -i interface [-p port] [-t] [-u]\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    return conn;
}