#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>

const char* get_protocol_name(uint8_t proto);

// callback function called by the pcap_loop for every packet
void packet_handler(u_char *args, 
                    const struct pcap_pkthdr *header, 
                    const u_char *packet) {
                        
    struct ether_header *eth_header = (struct ether_header *) packet;

    // check if the ether_type is ipv4 (0x0800 in network byte order)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // ipv4 header starts after Ethernet header
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        // convert source and dest IP addresses to strings 
        // inet_ntoa returns a pointer to a buffer, and rewrites buffer each call,
        // so we must copy
        strncpy(src_ip, inet_ntoa(ip_header->ip_src), INET_ADDRSTRLEN);
        strncpy(dst_ip, inet_ntoa(ip_header->ip_dst), INET_ADDRSTRLEN);

        printf("Source IP: %15s\t--->\tDestination IP: %15s\t(%s)\n",
               src_ip, dst_ip, get_protocol_name(ip_header->ip_p));
    }

}

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
const char* get_protocol_name(uint8_t proto) {
    switch (proto) {
        case 6: return "TCP";
        case 17: return "UDP";
        case 1: return "ICMP";
        default: return "OTHER";
    }
}

int main() {
    pcap_if_t *alldevs;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // try to get network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }

    // open the first network device
    handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldnt open device %s: %s", alldevs->name, errbuf);
        return 2;
    }

    printf("Using device: %s\n", alldevs->name);


    pcap_loop(handle, -1, packet_handler, NULL);
    
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}

