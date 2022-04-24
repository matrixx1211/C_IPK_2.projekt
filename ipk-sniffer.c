/**
 * @file main.c hlavní soubor
 * @author Marek Bitomský (xbitom00)
 * @brief hlavní soubor obsahující kód pro packet sniffer
 * @date 2022-04-23
 */

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <time.h>

#include "ipk-sniffer.h"

/**
 * @brief Vypíše nápovědu
 *
 * @param program název programu
 */
void print_help(char *program)
{
    // ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
    printf("--------------------------------------------------------------------------------------------------------------------------\n");
    printf("USAGE: %s [-i interface | --interface interface] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n", program);
    printf("\t-h           | --help                 open this help\n");
    printf("\t-i [string]  | --interface [string]   specify an interface\n");
    printf("\t-p [integer] | --port [integer]       set port to filter (src or dest)\n");
    printf("\t-t           | --tcp                  filter only TCP packets\n");
    printf("\t-u           | --udp                  filter only UDP packets\n");
    printf("\t-a           | --arp                  filter only ARP packets\n");
    printf("\t-m           | --icmp                 filter only ICMP packets\n");
    printf("\t-n [integer] | --num [integer]        set packet limit (default 1)\n");
}

/**
 * @brief Kontrola argumentů
 *
 * @param argc počet argumentů + 1 => název
 * @param argv pole argumentů
 * @return int návratová hodnota, jestli
 */
int check_args(int argc, char **argv, struct settings *s)
{
    int expected_count = 0;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    pcap_if_t *tmp;
    int pos = 1;
    size_t i;

    // nalezení všech interfaců
    if (pcap_findalldevs(&interfaces, error_buffer) < 0)
    {
        printf("Error in pcap_findalldevs(): %s.\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    for (i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--interface"))
        {
            // očekávaný počet argumentů
            expected_count += 2;
            // kontrola jestli počet argumentů bez jména je větší nebo roven indexu následujícího
            if (argc - 1 >= i + 1)
            {
                bool ok = true;
                for (int c = 0; c < strlen(argv[i + 1]); c++)
                {
                    if (!isalnum(argv[i + 1][c]))
                        ok = false;
                }

                if (ok)
                {
                    for (tmp = interfaces; tmp; tmp = tmp->next)
                        if (!strcmp(argv[i + 1], tmp->name))
                            s->interface = tmp->name;
                }
                else
                {
                    fprintf(stderr, "Error: Interface is not alnum.\n");
                    print_help(argv[0]);
                    exit(EXIT_FAILURE);
                }
            }
            else
            {
                fprintf(stderr, "Error: Interface name not entered.\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }
        }
        else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port"))
        {
            // očekávaný počet argumentů
            expected_count += 2;
            // kontrola jestli počet argumentů bez jména je větší nebo roven indexu následujícího
            if (argc - 1 >= i + 1)
            {
                bool ok = true;
                for (int c = 0; c < strlen(argv[i + 1]); c++)
                    if (!isdigit(argv[i + 1][c]))
                        ok = false;

                if (ok)
                    s->port = argv[i + 1];
                else
                {
                    fprintf(stderr, "Error: Port is not digit.\n");
                    print_help(argv[0]);
                    exit(EXIT_FAILURE);
                }
            }
            else
            {
                fprintf(stderr, "Error: Port number not entered.\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }
        }
        else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--tcp"))
        {
            expected_count++;
            s->tcp = true;
        }
        else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udp"))
        {
            expected_count++;
            s->udp = true;
        }
        else if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--arp"))
        {
            expected_count++;
            s->arp = true;
        }
        else if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--icmp"))
        {
            expected_count++;
            s->icmp = true;
        }
        else if (!strcmp(argv[i], "-n") || !strcmp(argv[i], "--num"))
        {
            // očekávaný počet argumentů
            expected_count += 2;
            // kontrola jestli počet argumentů bez jména je větší nebo roven indexu následujícího
            if (argc - 1 >= i + 1)
            {
                bool ok = true;
                for (int c = 0; c < strlen(argv[i + 1]); c++)
                    if (!isdigit(argv[i + 1][c]))
                        ok = false;

                if (ok)
                    s->num = atoi(argv[i + 1]);
                else
                {
                    fprintf(stderr, "Error: Number of packets is not digit.\n");
                    print_help(argv[0]);
                    exit(EXIT_FAILURE);
                }
            }
            else
            {
                fprintf(stderr, "Error: Number of packets not entered.\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }
        }
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
        {
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
        }
    }

    if (expected_count != (argc - 1))
    {
        fprintf(stderr, "Error: Expected count of parameters: %d, but got %d.\n", expected_count, argc - 1);
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (!strcmp(s->interface, ""))
    {
        printf("Error: Only avaiable interfaces on this device are: \n");
        for (tmp = interfaces; tmp; tmp = tmp->next)
            printf("%d:\t%s\n", pos++, tmp->name);
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }
}
/**
 * @brief vypisuje data packetu
 *
 * @param data data
 * @param length délka dat
 */
void print_data(const unsigned char *data, const unsigned int length)
{
    // proměnné pro výpis
    unsigned char c;
    unsigned int i, j, offset = 0;

    // procházení přes data
    for (i = 0; i < length; i++)
    {
        // po každém vypsaném řádku vypíšu offset
        if (((i % 16) == 0))
        {
            printf("0x%04x  ", offset);
        }
        // výpis dvojice
        c = data[i];
        printf("%02x ", c);
        // řešení poloprázdných řádku
        if (((i % 16) == 15) || (i == length - 1))
        {
            for (j = 0; j < 15 - (i % 16); j++)
                printf("   ");
            // mezera za hexidecimálním zápisem
            printf(" ");
            // výpis ASCII znaků
            for (j = (i - (i % 16)); j <= i; j++)
            {
                c = data[j];
                if ((c > 31) && (c < 127))
                    printf("%c", c);
                else
                    printf(".");
            }
            printf("\n");
            offset = offset + 16;
        }
    }
}

/**
 * @brief vypíše ipv4 adresu
 *
 * @param msg zadaná zpráva před ip adresou
 * @param ip_address ip adresa
 */
void print_ipv4_address(char *msg, __uint32_t ip_address)
{
    struct in_addr ip;
    ip.s_addr = ip_address;
    printf("%s: %s\n", msg, inet_ntoa(ip));
}

/**
 * @brief vypíše ipv6 adresu
 *
 * @param msg zadaná zpráva před ip adresou
 * @param ip_address ip adresa
 */
void print_ipv6_address(char *msg, struct in6_addr ip_address)
{
    char addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip_address, addr, INET6_ADDRSTRLEN);
    printf("%s: %s\n", msg, addr);
}

/**
 * @brief podle protokolu dělá určitý výpis
 *
 * @param protocol číslo protokolu
 * @param packet packet
 * @param length délka dat
 * @param ipv6 pravdivostní hodnota zda jde o ipv6
 */
void ip_protocol(int protocol, const u_char *packet, unsigned int length, bool ipv6)
{
    // rozlišení jestli se jedná o ipv4 nebo ipv6
    int header_size = sizeof(struct ipv4_header);
    if (ipv6)
        header_size = sizeof(struct ipv6_header);
    packet = packet + header_size;

    // ICMPv4
    if (protocol == 1)
    {
        // výpis dat
        print_data((packet + sizeof(uint16_t) + (3 * sizeof(unsigned char))), length);
    }
    // TCP
    else if (protocol == 6)
    {
        struct tcp_header *tcp_segment = (struct tcp_header *)packet;
        // výpis portů pro TCP
        printf("src port: %d\n", ntohs(tcp_segment->src_port));
        printf("dst port: %d\n", ntohs(tcp_segment->dest_port));

        // výpis dat
        print_data((packet + sizeof(struct tcp_header)), length);
    }
    // UDP
    else if (protocol == 17)
    {
        struct udp_header *udp_segment = (struct udp_header *)packet;
        // výpis portů pro UDP
        printf("src port: %d\n", ntohs(udp_segment->src_port));
        printf("dst port: %d\n", ntohs(udp_segment->dst_port));

        // výpis dat
        print_data((packet + sizeof(struct udp_header)), length);
    }
    // ICMPv6
    else if (protocol == 58)
    {
        printf("\tICMPv6 Packet:\n");
    }
}

/**
 * @brief vypíše čas v RFC3339 formátu
 */
void timestamp_print()
{
    time_t now;
    time(&now);
    struct tm *pointer = localtime(&now);
    char buffer[100];
    size_t len = strftime(buffer, sizeof buffer - 1, "%FT%T%z", pointer);
    // posun 2 posledních čísel
    if (len > 1)
    {
        char minute[] = {buffer[len - 2], buffer[len - 1], '\0'};
        sprintf(buffer + len - 2, ":%s", minute);
    }
    printf("timestamp: %s\n", buffer);
}

/**
 * @brief parsuje packet a volá funkce dle vlastností packetu
 *
 * @param args vyžaduje pcap_loop
 * @param header hlavička s délkou
 * @param packet paket
 */
void parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // výpis času
    timestamp_print();

    // přetypování packetu na ethernetový rámec
    struct ethernet_frame *eth_frame = (struct ethernet_frame *)packet;

    // přetypování packetu na ipv4/6 header dle protokolu v eth rámci
    struct ipv4_header *ipv4_packet;
    struct ipv6_header *ipv6_packet;

    // struktura určená pro pozdější výpis
    printf("src MAC: %s\n", ether_ntoa((struct ether_addr *)eth_frame->source_mac_addr));
    printf("dst MAC: %s\n", ether_ntoa((struct ether_addr *)eth_frame->dest_mac_addr));

    // výpis délky
    printf("frame length: %d bytes\n", header->len);

    // IPv4
    if (eth_frame->protocol == 8)
    {
        // uložení IPv4 packetu s příslušným posunem od ethernetové hlavičky
        ipv4_packet = (struct ipv4_header *)(packet + ETH_HEADER_LENGTH);
        print_ipv4_address("src IP", ipv4_packet->src_addr);
        print_ipv4_address("dst IP", ipv4_packet->dst_addr);

        ip_protocol(ipv4_packet->protocol, packet + ETH_HEADER_LENGTH, header->len, false);
    }
    // IPv6
    else if (eth_frame->protocol == 56710)
    {
        // uložení IPv6 packetu s příslušným posunem od ethernetové hlavičky
        ipv6_packet = (struct ipv6_header *)(packet + ETH_HEADER_LENGTH);
        print_ipv6_address("src IP", ipv6_packet->src_addr);
        print_ipv6_address("dst IP", ipv6_packet->dst_addr);

        ip_protocol(ipv6_packet->next_header, packet + ETH_HEADER_LENGTH, header->len, true);
    }
    // ARP
    else if (eth_frame->protocol == 1544)
    {
        struct arp_header *arp_header = (struct arp_header *)(packet + ETH_HEADER_LENGTH);
        print_ipv4_address("src IP", arp_header->src_addr);
        print_ipv4_address("dst IP", arp_header->dst_addr);
    }

    printf("\n");
}

/**
 * @brief Vytvoří řetězec pro filtr
 *
 * @param filter řetěžec filtru
 * @param port číslo portu
 * @param arp pravdivostní hodnota pro arp
 * @param icmp pravdivostní hodnota pro icmp
 * @param tcp pravdivostní hodnota pro tcp
 * @param udp pravdivostní hodnota pro udp
 */
void create_filter(char *filter, char *port, bool tcp, bool udp, bool icmp, bool arp)
{
    // pokud není nic nastaveno, tak nastavím filtr, aby bral všechno s ošetřením portu
    if (!arp && !icmp && !tcp && !udp)
    {
        if (*port)
            sprintf(filter, "arp or icmp or icmp6 or tcp port %s or udp port %s", port, port);
        else
            sprintf(filter, "arp or icmp or icmp6 or tcp or udp");
    }
    // pokud je arp, tak nastavím filtr pro něj s ošetřením stavů
    if (arp)
    {
        if (*filter)
            strcat(filter, " or ");
        strcat(filter, "arp");
    }

    // pokud je icmp, tak nastavím filtr pro něj s ošetřením stavů
    if (icmp)
    {
        if (*filter)
            strcat(filter, " or ");
        strcat(filter, "icmp or icmp6");
    }

    // pokud je tcp, tak nastavím filtr pro něj s ošetřením stavů
    if (tcp)
    {
        if (*filter)
            strcat(filter, " or ");

        strcat(filter, "tcp");

        if (*port)
        {
            strcat(filter, " port ");
            strcat(filter, port);
        }
    }

    // pokud je udp, tak nastavím filtr pro něj s ošetřením stavů
    if (udp)
    {
        if (*filter)
            strcat(filter, " or ");
        strcat(filter, "udp");

        if (*port)
        {
            strcat(filter, " port ");
            strcat(filter, port);
        }
    }
}

/**
 * @brief zpracovává celý program voláním funkcí
 *
 * @param argc počet argumentů
 * @param argv hodnoty argumentů
 * @return int návratová hodnota
 */
int main(int argc, char **argv)
{
    // kontrola parametrů včetně jejich kombinací s využitím vlastní struktury pro nastavení
    struct settings s;
    s.port = "";
    s.num = 1;
    s.interface = "";
    s.tcp = false;
    s.udp = false;
    s.icmp = false;
    s.arp = false;
    check_args(argc, argv, &s);

    // buffer na errory zprávy
    char error_buffer[PCAP_ERRBUF_SIZE];

    struct bpf_program filter_pointer;
    bpf_u_int32 netp, maskp;

    if (pcap_lookupnet(s.interface, &netp, &maskp, error_buffer) == -1)
    {
        fprintf(stderr, "Error: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    // otevření odposlouchání na rozhraní specifikovaném v argumentu
    pcap_t *handle = pcap_open_live(s.interface, BUFSIZ, 1, s.num, error_buffer);
    if (!handle)
    {
        fprintf(stderr, "Error: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    // vytvoření filtru
    char filter[200] = "";
    create_filter(filter, s.port, s.tcp, s.udp, s.icmp, s.arp);

    // kompilace řetězce filtru na pcap filtr
    if (pcap_compile(handle, &filter_pointer, filter, 0, netp) == -1)
    {
        fprintf(stderr, "Error: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    // nastavení filtru
    if (pcap_setfilter(handle, &filter_pointer) == -1)
    {
        fprintf(stderr, "Error: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }

    // vytvoření loopu, který bude brát packety po dobu než jich bude s.num
    pcap_loop(handle, s.num, parse_packet, NULL);
    // ukončení loopu
    pcap_close(handle);

    // ukončení bez chyby
    return EXIT_SUCCESS;
}