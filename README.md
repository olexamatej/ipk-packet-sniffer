# Project 2 - ZETA: Network sniffer

Matej Olexa (xolexa03) 21.4.2024

## Obsah
[Popis](#popis)  
[Spustenie](#Spustenie)  
[Zoznam odovzdaných súborov](#Zoznam-odovzdaných-súborov)  

## Stručný popis

Implementácia sledovača packetov `packet sniffer` pomocou použitia knižnice `pdap` na základe požiadavkov zadania varianty `ZETA` pre IPK.

## Spustenie

`./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}`

`-i | --interface` povinný parameter určujúci rozhranie na ktorom majú byť packety sledované  
`-t | --tcp` parameter určujúci zachytávanie iba TCP paketov  
`-u | --udp` parameter určujúci zachytávanie iba UDP paketov  
`-p` rozširuje parametre na určenie TCP/UDP paketov o konkrétny port, na ktorom   sú sledované pakety  
`--port-source` rozširuje parametre na určenie TCP/UDP paketov o konkrétny zdrojový port, na ktorom sú sledované pakety  
`--port-destination` rozširuje parametre na určenie TCP/UDP paketov o konkrétny cieľový port, na ktorom sú sledované pakety  
`--icmp4` zobrazí pakety typu ICMPv4  
`--icmp6` zobrazí pakety typu ICMPv6  
`--arp` zobrazí ARP rámce  
`--igmp` zobrazí pakety typu IGMP  
`--mld` zobrazí pakety typu MLD (podmnožina ICMPv6)  
`--ndp` zobrazí pakety typu NDP (podmnožina ICMPv6)  
`-n` špecifikuje počet paketov, ktoré má aplikácia zobraziť  

## Zoznam odovzdaných súborov

- `arg_parser.cpp`
- `arg_parser.h`
- `connection.cpp`
- `connection.hpp`
- `main.cpp`
- `sniffer.cpp`
- `sniffer.h`

## Implementácia






