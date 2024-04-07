#include "arg_parser.h"
#include "connection.h"

int main(int argc, char *argv[])
{
    Connection conn = parse_arg(argc, argv);
    conn.print_connection();

    return(0);
}