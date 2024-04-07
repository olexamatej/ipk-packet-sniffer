#include "sniffer.h"
#include <chrono>
#include <ctime>
#include <iomanip>

int Sniffer::sniff(Connection conn){
    pcap_t *handle;         // Session handle
    char errbuf[PCAP_ERRBUF_SIZE]; // Error string
    struct bpf_program fp;      //compiled filter
    char filter_exp[] = ""; //filter expression
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
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
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