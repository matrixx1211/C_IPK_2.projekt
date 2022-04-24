/**
 * @file main.h hlavičkový soubor s prototypy funkcí
 * @author Marek Bitomský (xbitom00)
 * @date 2022-04-23
 */

#ifndef __IPK_PACKET_SNIFFER_H__
#define __IPK_PACKET_SNIFFER_H__

#include <stdbool.h>

#define ETH_ADDRESS_LENGTH 6
#define ETH_HEADER_LENGTH 14

/* Struktura pro ethernet rámec protokolu */
struct ethernet_frame
{
    unsigned char source_mac_addr[ETH_ADDRESS_LENGTH];
    unsigned char dest_mac_addr[ETH_ADDRESS_LENGTH];
    unsigned short protocol;
};

/* Struktura pro hlavičku IPv4 protokolu */
struct ipv4_header
{
    unsigned char ihl : 4;
    unsigned char version : 4;
    unsigned char type_of_service;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_and_fragment_offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short header_checksum;
    unsigned int src_addr;
    unsigned int dst_addr;
};

/* Struktura pro hlavičku IPv6 protokolu */
struct ipv6_header
{
    u_int8_t version : 4, traffic_class_high : 4;
    u_int8_t traffic_class_low : 4, flow_label_high : 4;
    uint16_t flow_label_low;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
};

/* Struktura pro hlavičku ARP protokolu */
struct arp_header
{
    uint16_t htype;       
    uint16_t ptype;       
    uint8_t hlen;         
    uint8_t plen;         
    uint16_t op;          
    uint8_t src_mac_addr;         
    uint32_t src_addr;         
    uint8_t dst_mac_addr;         
    uint32_t dst_addr;         
};

/* Struktura pro hlavičku tcp protokolu */
struct tcp_header
{
    unsigned short src_port;
    unsigned short dest_port;
    u_int32_t sequence;
    u_int32_t acknowledgment;
    unsigned char reserved : 4;
    unsigned char data_offset : 4;
    unsigned char flags;
    unsigned short window_size;
    unsigned short checksum;
    unsigned short urgent_pointer;
};

/* Struktura pro hlavičku udp protokolu */
struct udp_header
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

/* Struktura pro parametrové nastavení */
struct settings
{
    char *port;
    char *interface;
    bool tcp;
    bool udp;
    bool icmp;
    bool arp;
    int num;
};

/* Vypíše nápovědu jako parametr bere název programu */
void print_help(char *);
/* Kontroluje parametry */
int check_args(int, char **, struct settings *);
/* Funkce vypisuje data v daném formátu */
void print_data(const unsigned char *, const unsigned int);
/* Funkce vypisuje ipv4 adresu se zprávou */
void print_ipv4_address(char *, __uint32_t);
/* Funkce vypisuje ipv6 adresu se zprávou */
void print_ipv6_address(char *, struct in6_addr);
/* Funkce dle protokolu volá konkrétní funkce */
void ip_protocol(int, const u_char *, unsigned int, bool);
/* Funkce vypisuje časové razítko */
void timestamp_print();
/* Funkce parsuje paket a volá funkce dle protokolu */
void parse_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
/* Funkce vytváří filtr podle zadaných argumentů na příkazové řádce */
void create_filter(char *, char *, bool, bool, bool, bool);
/* Hlavní funkce */
int main(int, char **);

#endif //__IPK_PACKET_SNIFFER_H__
