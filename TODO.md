* `--port-destination 23` (extends previous two parameters to filter TCP/UDP based on port number; if this parameter is not present, then no filtering by port number occurs; if the parameter is given, the given port can occur in destination part of TCP/UDP headers).
* `--port-source 23` (extends previous two parameters to filter TCP/UDP based on port number; if this parameter is not present, then no filtering by port number occurs; if the parameter is given, the given port can occur in source part of TCP/UDP headers).

 only -i/--interface is specified without a value (and any other parameters are unspecified), a list of active interfaces is printed (additional information beyond the interface list is welcome but not required).

metju@swagpc:~/ipk/proj2$ sudo ./ipk-sniffer -i eth0 -u --port-source 1234
If port is specified, either -t or -u must be specified.

 FIX SEGFAULT AT -n 500


 metju@swagpc:~/ipk/proj2$ sudo ./ipk-sniffer -i lo -t --port-destination 4567
timestamp: 4461264-12-14T09:32:32+0100
Segmentation fault