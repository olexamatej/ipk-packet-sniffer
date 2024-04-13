#include "arg_parser.h"
#include "connection.h"
#include "sniffer.h"



#include <csignal> // Add this line to include the <csignal> header

void sigint_handler(int signum) {
    std::cout << "Interrupt signal received" << std::endl;
    
    exit(0);
}

int main(int argc, char *argv[])
{
    //handle sigint
    signal(SIGINT, sigint_handler);

    Connection conn = parse_arg(argc, argv);
    Sniffer sniffer(conn);

    if(sniffer.sniff() != 0){
        return(1);
    }

    return(0);
}