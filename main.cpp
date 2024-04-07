#include "arg_parser.h"
#include "connection.h"
#include "sniffer.h"

int main(int argc, char *argv[])
{
    Connection conn = parse_arg(argc, argv);
    // conn.print_connection();
    Sniffer sniffer(conn);

    sniffer.sniff();

    return(0);
}