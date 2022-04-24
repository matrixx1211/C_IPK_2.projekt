Autor: Marek Bitomský
# Packet sniffer
Program slouží pro výpis paketů a filtrování jaké pakety se mají vypisovat.
Filtrování se nastavuje na příkazové řádce pomocí argumentů, lze nastavit 
filtrování tcp, udp, arp, icmp u protokolů a ještě jde nastavit port případně
rozhraní.

## Spuštění
Program se spouští pomocí příkazu:
`./ipk-sniffer -i [interface]` - toto platí v případě bez filtru
Pro použití filtru lze zadat ještě kombinaci některých těchto argumentů
jako je třeba `-t | --tcp`, `-u | --udp`, `-a | --arp`, `-m | --icmp` nebo
`-p [port] | --port [port]`.
Ještě lze omezit počet packetů, který je ve výchozím stavu nastaven na 1 a to
pomocí `-n [počet] | --num [počet]`.

## Kompilace
Kompilace se provádí pomocí příkazu `make`. Otestováná na Ubuntu 20.04.

## Testování
Program byl otestován pomocí `make runX` a dalších příkazů z makefilu, 
kde **X** v runx znamená číslo testu možnosti 1-8. Následně jsem používat
linux příkazy `arping`, `ping`, `ping6`, `nc` a `curl` pro ověření konkrétních
případů.

## Omezení
Program neumí zpracovávat většinu z ARP protokolu.
