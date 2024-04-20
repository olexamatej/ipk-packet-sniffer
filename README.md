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

## Teória k implementácii

Sledovač paketov zachytáva pakety zo sieťovej komunikácie na úrovni rozhraní. Knižnica PCAP umožňuje filtráci ua zachytávanie paketov rôznych rozhraní, ktoré sú následne spracované a vypísané na stdout. Zachytávanie paketov je v svojom jadre rovnaké pre všetky typy paketov, ale v niektorých častiach spracovania sa líši. Z tohto dôvodu je hlavné sledovanie rozdelené pre IPv4, IPv6 pakety a ARP rozhranie.

### IPv4 pakety
IPv4 pakety sú základom prenosu dát pomocou `Internet Protocol version 4`. Každý paket má svoju hlavičku `header` a dáta `payload`. Hlavička obsahuje informácie o prenose dát s informáciami ako je dĺžka paketu, IP adresy a kontrolný súčet `checksum`.

Veľkosť hlavičky tohto paketu nieje vopred daná a následuju ju dáta `payload`. IP adresa je dlhá 32 bitov.  

### IPv6 pakety
IPv6 pakety slúžia na prenos dát v `Internet Protocol version 6`. Každý paket má svoju hlavičku `header` a dáta `payload`. Hlavička obsahuje informácie pre prenos dát a ich doručenie, ako sú IP adresy, dĺžka paketu, `traffic class`, `flow label`, `hop limit` a ďalšie pole hlavičky, ktoré určuje aký typ dát je prenášaný v `payload`.

Veľkosť hlavičky tohto paketu je 40 byteov. Hlavička taktiež obsahuje informácie naviac, oproti IPv4 paketom. IPv6 podporuje rozšírenú hlavičku, ktorá obsahuje ďalšie informácie a rozšírenie. IPv6 pakety neobsahujú konečný súčet. IP adresa je dlhá 128 bitov a je v hexadecimálnom formáte.

### ARP pakety
ARP pakety sú používané pre mapovaní IP adries na MAC adresy na lokálnej sieti. Sú zložené z hlavičky `header` nasledovanou poľami pre zdrojovú a cieľovú MAC adresu a zdrojovú a cieľovú IP adresu. Hlavička obsahuje informácie o typu hardwareu, typ protokolu, operačného kódu `operation code` a veľkosti protokolových adries.

## Implementácia

Pri 





