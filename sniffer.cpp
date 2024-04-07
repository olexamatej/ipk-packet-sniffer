#include "sniffer.h"
#include <chrono>
#include <ctime>
#include <iomanip>

Sniffer::Sniffer(Connection conn){
    this->conn = conn;
}

std::string Sniffer::get_filters(){
    std::string filters = "";
    if(conn.arp){
        filters += "arp ||";
    }
    if(conn.icmp4){
        filters += "icmp ||";
    }
    if(conn.icmp6){
        filters += "icmp6 ||";
    }
    if(conn.igmp){
        filters += "igmp ||";
    }
    if(conn.mld){
        filters += "icmp6 and ip6[40] == 130 ||";
    }
    if(conn.tcp){
        filters += "tcp ||";
    }
    if(conn.udp){
        filters += "udp ||";
    }
    if(conn.ndp){
        filters += "icmp6 and (ip6[40] == 133 or ip6[40] == 134 or ip6[40] == 135 or ip6[40] == 136) ||";
    }
    if(conn.port != 0){
        filters += "port " + std::to_string(conn.port) + " ";
    }
    if(filters[filters.size()] == '|'){
        filters.pop_back();
        filters.pop_back();
    }
    return filters;
}

int Sniffer::sniff(){
    pcap_t *handle;         // Session handle
    char errbuf[PCAP_ERRBUF_SIZE]; // Error string
    struct bpf_program fp;      //compiled filter
    std::string filter_exp = "icmp6 and ip6[40] == 130"; //filter expression
    bpf_u_int32 mask;       // subnet mask
    bpf_u_int32 net;        // IP
    struct pcap_pkthdr header;   //pcap header
    const u_char *packet;       //packet

    //getting interface
    const char* dev = conn.interface.c_str();
    
    //getting netmask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    //applying filter
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
        return(2);
    }
    //grabbing packet
    packet = pcap_next(handle, &header);

    //parse ip header
    struct ip *iph = (struct ip *)(packet + 14);
    //parse tcp header
    struct tcphdr *tcph=(struct tcphdr*)(packet + 14 + iph->ip_hl*4);


    //change header.ts.tv_sec to ISO format

    std::time_t ts = header.ts.tv_sec;
    std::tm* tm = std::localtime(&ts);
    std::cout << "timestamp: " << std::put_time(tm, "%FT%T%z") << std::endl;

    //src mac
    std::cout << "src MAC: ";
    for(int i = 6; i < 12; i++){
        printf("%02x", packet[i]);
        if(i < 11){
            printf(":");
       }
    }
    std::cout << std::endl;

    //dst mac
    std::cout << "dst MAC: ";
    for(int i = 0; i < 6; i++){
        printf("%02x", packet[i]);
        if(i < 5){
            printf(":");
        }
    }
    std::cout << std::endl;
 
    //frame length
    std::cout << "frame length: " << header.len << std::endl;
    //src and dst ip
    std::cout << "src ip: " << inet_ntoa(iph->ip_src) << "\n";
    std::cout << "dst ip: " << inet_ntoa(iph->ip_dst) << "\n";

    //port
    std::cout << "src port: " << ntohs(tcph->source) << "\n";
    std::cout << "dst port: " << ntohs(tcph->dest) << "\n";


    //print hexdump
    for (int i = 0; i < header.len; ++i) {
    // byte offset at start
    if (i % 16 == 0)
        printf("0x%04x  ", i);

    // byte in hex
    printf("%02x ", packet[i]);

    // ascii at the end
    if (i % 16 == 7)
        printf(" ");  // space in middle
    if (i % 16 == 15 || i == header.len - 1) {
        for (int j = 0; j < 15 - i % 16; ++j)
            printf("   ");  // extra spaces if not full line
        if (i % 16 < 8)
            printf(" ");  // extra space
        printf(" ");
        for (int j = i - i % 16; j <= i; ++j) {
            char ch = isprint(packet[j]) ? packet[j] : '.';
            printf("%c", ch);
        }
        printf("\n");
    }
}
    

    pcap_close(handle);
    return(0);
}