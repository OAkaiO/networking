#include "test-arp.h"



static void debug_print_mac (struct MacAddress mac) {
    fprintf(stderr, "%02X:%02X:%02X:%02X:%02X:%02X \n", mac.mac[0], mac.mac[1], mac.mac[2], mac.mac[3], mac.mac[4], mac.mac[5]);
}



static void debug_print_ipv4_n (struct in_addr ip) {
    ip.s_addr = htonl(ip.s_addr);
    char buf[INET_ADDRSTRLEN];
    fprintf(stderr, "%s\n", inet_ntop (AF_INET, &ip, buf, sizeof (buf)));
}

static void debug_print_ipv4 (struct in_addr ip) {
    char buf[INET_ADDRSTRLEN];
    fprintf(stderr, "%s", inet_ntop (AF_INET, &ip, buf, sizeof (buf)));
}

static void debug_print_frame(uint8_t *bytes, ssize_t size){
    // print the whole hexdump to see
    for (int i = 0; i < size; ++i) {
        fprintf(stderr, "%02x ", bytes[i]);
        if (i % 81 == 80) {
            fprintf(stderr, "\n");
        }
    }
    fprintf(stderr, "\n");
}



static void debug_print_glab_header(struct GLAB_MessageHeader gmh){
    //fprintf(stderr, "glab size: \t0x%04x\n", ntohs(gmh.size));
    fprintf(stderr, "glab size: \t%ul\n", ntohs(gmh.size));
    //fprintf(stderr, "glab ctrl: \t0x%04x\n", ntohs(gmh.type));
    fprintf(stderr, "glab ctrl: \t%ul\n", ntohs(gmh.type));
}

static void debug_print_ethernet_header(struct EthernetHeader eh){
    fprintf(stderr, "DEST MAC: \t");
    debug_print_mac(eh.dst);
    fprintf(stderr, "SRC  MAC: \t");
    debug_print_mac(eh.src);
    fprintf (stderr,"ETH TAG: \t0x%04x\n", ntohs(eh.tag));
}


static void debug_print_arp_header(struct ArpHeaderEthernetIPv4 ah) {
    fprintf(stderr, "OPERATION: \t0x%04x\n", ntohs(ah.oper));
    fprintf(stderr, "SEND MAC: \t");
    debug_print_mac(ah.sender_ha);
    fprintf(stderr, "SEND IP: \t");
    debug_print_ipv4_n(ah.sender_pa);
    fprintf(stderr, "TARG MAC: \t");
    debug_print_mac(ah.target_ha);
    fprintf(stderr, "TARG IP: \t");
    debug_print_ipv4_n(ah.target_pa);
    fprintf(stderr, "\n");
    fprintf(stderr, "\n");
}

static void debug_print_humanreadable_frame(const uint8_t *bytes){
    debug_print_glab_header(*(struct GLAB_MessageHeader*) &bytes[0]);
    debug_print_ethernet_header(*(struct EthernetHeader*) &bytes[sizeof(struct GLAB_MessageHeader)]);
    debug_print_arp_header(*(struct ArpHeaderEthernetIPv4*) &bytes[sizeof(struct GLAB_MessageHeader)+sizeof(struct EthernetHeader)]);
}

/*
static void debug_print_arp_packet(struct ArpPacket packet){
    debug_print_glab_header(packet.gmh);
    debug_print_ethernet_header(packet.eh);
    debug_print_arp_header(packet.ah);
}*/

static void debug_print_frame_range(uint8_t *bytes, int start, ssize_t size){
    // print the whole hexdump to see
    for (int i = start; i < size; ++i) {
        fprintf(stderr, "%02x ", bytes[i]);
        if (i % 81 == 80) {
            fprintf(stderr, "\n");
        }
    }
    //fprintf(stderr, "\n");
}
