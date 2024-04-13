#include "arg_parser.h"
#include "connection.h"
#include "sniffer.h"

int main(int argc, char *argv[])
{
    Connection conn = parse_arg(argc, argv);
    Sniffer sniffer(conn);

    if(sniffer.sniff() != 0){
        return(1);
    }

    return(0);
}