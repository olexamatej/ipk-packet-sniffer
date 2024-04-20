* `--port-destination 23` (extends previous two parameters to filter TCP/UDP based on port number; if this parameter is not present, then no filtering by port number occurs; if the parameter is given, the given port can occur in destination part of TCP/UDP headers).
* `--port-source 23` (extends previous two parameters to filter TCP/UDP based on port number; if this parameter is not present, then no filtering by port number occurs; if the parameter is given, the given port can occur in source part of TCP/UDP headers).

 only -i/--interface is specified without a value (and any other parameters are unspecified), a list of active interfaces is printed (additional information beyond the interface list is welcome but not required).

 FIX SEGFAULT AT -n 500