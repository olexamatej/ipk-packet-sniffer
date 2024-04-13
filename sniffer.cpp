#include "sniffer.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <netinet/ether.h>
#include <netinet/ip6.h>
    #include <netinet/udp.h>


Sniffer::Sniffer(Connection conn)
{   
    this->handle = NULL;
    this->conn = conn;
}

void Sniffer::print_frame_length(const struct pcap_pkthdr header)
{
    std::cout << "frame length: " << header.len << std::endl;
}

void Sniffer::print_mac(const u_char *packet, int start, const char *label)
{
    std::cout << label;
    for (int i = start; i < start + 6; i++)
    {
        printf("%02x", packet[i]);
        if (i < start + 5)
        {
            printf(":");
        }
    }
    std::cout << std::endl;
}

void Sniffer::print_hexdump(const u_char *packet, int len)
{
    for (int i = 0; i < len; ++i)
    {
        // byte offset at start
        if (i % 16 == 0)
            printf("0x%04x  ", i);

        // byte in hex
        printf("%02x ", packet[i]);

        // ascii at the end
        if (i % 16 == 7)
            printf(" "); // space in middle
        if (i % 16 == 15 || i == len - 1)
        {
            for (int j = 0; j < 15 - i % 16; ++j)
                printf("   "); // extra spaces if not full line
            if (i % 16 < 8)
                printf(" "); // extra space
            printf(" ");
            for (int j = i - i % 16; j <= i; ++j)
            {
                char ch = isprint(packet[j]) ? packet[j] : '.';
                printf("%c", ch);
            }
            printf("\n");
        }
    }
}

void Sniffer::print_timestamp(const struct pcap_pkthdr header)
{
    std::time_t ts = header.ts.tv_sec;
    std::tm *tm = std::localtime(&ts);
    std::cout << "timestamp: " << std::put_time(tm, "%FT%T%z") << std::endl;
}

void Sniffer::print_IP_port(const u_char *packet, struct ether_header *eth) {
    uint16_t ether_type = ntohs(eth->ether_type);

    if (ether_type == ETH_P_IP) {
        printIPv4(packet);
    } else if (ether_type == ETH_P_IPV6) {
        printIPv6(packet);
    } else if (ether_type == ETH_P_ARP) {
        printARP(packet);
    }
}

void Sniffer::printIPv4(const u_char *packet) {
    struct ip *iph = (struct ip *)(packet + 14);
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4);

    std::cout << "src IP: " << inet_ntoa(iph->ip_src) << "\n";
    std::cout << "dst IP: " << inet_ntoa(iph->ip_dst) << "\n";
    std::cout << "src port: " << ntohs(tcph->source) << "\n";
    std::cout << "dst port: " << ntohs(tcph->dest) << "\n";
}

void Sniffer::printIPv6(const u_char *packet) {
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(packet + 14);
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + 40);
    char src_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6h->ip6_src, src_ip, INET6_ADDRSTRLEN);

    std::cout << "src IP: " << src_ip << "\n";
    std::cout << "src port: " << ntohs(tcph->source) << "\n";
    std::cout << "dst port: " << ntohs(tcph->dest) << "\n";
}

void Sniffer::printARP(const u_char *packet) {
    struct ether_arp *arp = (struct ether_arp *)(packet + 14);

    std::cout << "src IP: ";
    for (int i = 0; i < 4; i++) {
        printf("%d", arp->arp_spa[i]);
        if (i < 3) {
            printf(".");
        }
    }
    std::cout << std::endl;

    std::cout << "dst IP: ";
    for (int i = 0; i < 4; i++) {
        printf("%d", arp->arp_tpa[i]);
        if (i < 3) {
            printf(".");
        }
    }
    std::cout << std::endl;
}



std::string Sniffer::get_filters()
{   
    std::string filters = "";

    if(conn.port_dst != 0){
        filters += "dst port " + std::to_string(conn.port_dst) + "||";
    }
    if(conn.port_src != 0){
        filters += "src port " + std::to_string(conn.port_src) + "&&";
    }
    //

    if (conn.tcp && conn.udp)
    {
        filters += "(tcp || udp) &&";
    }
    else if (conn.udp && !conn.tcp)
    {
        filters += "udp &&";
    }
    else if (conn.tcp && !conn.udp)
    {
        filters += "tcp &&";
    }
    filters += "(";
    if (conn.ndp)
    {
        filters += "icmp6 and (ip6[40] == 133 or ip6[40] == 134 or ip6[40] == 135 or ip6[40] == 136) ||";
    }
    if (conn.arp)
    {
        filters += "arp ||";
    }
    if (conn.icmp4)
    {
        filters += "icmp ||";
    }
    if (conn.icmp6)
    {
        filters += "icmp6 ||";
    }
    if (conn.igmp)
    {
        filters += "igmp ||";
    }
    if (conn.mld)
    {
        filters += "icmp6 and ip6[40] == 130";
    }
    // if there is ( at the end of the string, remove it

    if(filters.size() < 2){
        return "";
    }

    if (filters[filters.size() - 1] == '|')
    {
        filters.pop_back();
        filters.pop_back();
        filters += ")";
    }
    else if (filters[filters.size() - 1] == '(')
    {
        filters.pop_back();
        filters.pop_back();
        filters.pop_back();
    }


    return filters;
}

int Sniffer::init_pcap() {
    char errbuf[PCAP_ERRBUF_SIZE]; // Error string
    struct bpf_program fp;         // compiled filter
    std::string filters = get_filters();

    std::string filter_exp = filters; // filter expression
    bpf_u_int32 mask;                 // subnet mask
    bpf_u_int32 net;                  // IP

    // getting interface
    const char *dev = conn.interface.c_str();

    // getting netmask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }
    // applying filter
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
        return (2);
    }

    return 0;
}

int Sniffer::sniff() {
    struct pcap_pkthdr header;        // pcap header
    const u_char *packet;             // packet

    if(init_pcap() != 0){
        return 2;
    }

    for(int i = 0; i < conn.num_packets; i++){
        
        
        packet = pcap_next(this->handle, &header);

        // parse ethernet header
        struct ether_header *eth = (struct ether_header *)packet;

        struct ip *iph = (struct ip *)(packet + 14);
        
        print_timestamp(header);
        print_mac(packet, 6, "src MAC: ");
        print_mac(packet, 0, "dst MAC: ");
        print_frame_length(header);
        print_IP_port(packet, eth);
        print_hexdump(packet, header.len);
    }

    pcap_close(handle);
    return (0);
}

