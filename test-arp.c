#include <linux/if_packet.h>
#include "test-arp.h"
#include "debug.h"

// #include "print.c"

/**
 * Should we print (interesting|debug) messages that can happen during
 * normal operation?
 */
#define DEBUG 1

/**
 * Maximum size of a message.
 */
#define MAX_SIZE (65536 + sizeof (struct GLAB_MessageHeader))

/**
 * Should we filter packets by MAC and only pass on packets for
 * this interface (or multicast)?
 */
#define FILTER_BY_MAC 0

/**
 * Where is the VLAN tag in the Ethernet frame?
 */
#define VLAN_OFFSET (2 * MAC_ADDR_SIZE)

struct vlan_tag {
    uint16_t vlan_tpid;        /* ETH_P_8021Q */
    uint16_t vlan_tci;        /* VLAN TCI */
};

/**
 * Check if VLAN TCI provided is valid.
 */
#define VLAN_VALID(hdr, hv) ((hv)->tp_vlan_tci != 0 || ((hdr)->tp_status & TP_STATUS_VLAN_VALID))

/**
 * Compute the TPID given the AUX Data.
 */
#define VLAN_TPID(hdr, hv) (((hv)->tp_vlan_tpid || ((hdr)->tp_status & TP_STATUS_VLAN_TPID_VALID)) ? (hv)->tp_vlan_tpid : ETH_P_8021Q)


#ifndef _LINUX_IN6_H
/**
 * This is in linux/include/net/ipv6.h, but not always exported...
 */
struct in6_ifreq {
    struct in6_addr ifr6_addr;
    uint32_t ifr6_prefixlen;
    unsigned int ifr6_ifindex;
};
#endif

#define MAC_ADDR_SIZE 6

#define MAX(a, b) ((a) > (b))?(a):(b)

/**
 * Information about an interface.
 */
struct Interface {

    /**
     * Set to our MAC address.
     */
    uint8_t my_mac[MAC_ADDR_SIZE];

    /**
     * File descriptor for the interface.
     */
    int fd;

    /**
     * The buffer filled by reading from @e fd. Plus some extra
     * space for VLAN tag synthesis.
     */
    unsigned char buftun[MAX_SIZE + sizeof(struct vlan_tag)];

    /**
     * Current offset into @e buftun for writing to #child_stdin.
     */
    unsigned char *buftun_off;

    /**
     * Number of bytes in @e buftun (offset for reading more),
     * may start at an offset!
     */
    size_t buftun_size;

    /**
     * Number of bytes READY in @e buftun_off for current ready message.
     * Equals @e buftun_size for normal interfaces, but may differ for
     * control (cmd_line).
     */
    size_t buftun_end;

    /**
     * index of interface
     */
    struct ifreq if_idx;

};


int meta(int argc, char **argv);

int run_cmd(char *cmd) {
    /*
     * The buffer filled by reading from child's stdout, to be passed to some fd
     */
    unsigned char bufin[MAX_SIZE];
    /* bytes left to write from 'bufin_write' to 'current_write' */
    ssize_t bufin_write_left = 0;
    /* read stream offset in 'bufin' */
    size_t bufin_rpos = 0;
    /* write stream offset into 'bufin' */
    unsigned char *bufin_write_off = NULL;
    /* write refers to reading from child's stdout, writing to index 'current_write' */
    struct Interface *current_write = NULL;
    fd_set fds_w;
    fd_set fds_r;
    int fmax;
    /* We treat command-line input as a special 'network interface' */
    struct Interface cmd_line;

    /* read refers to reading from fd, currently writing to child's stdin */
    struct Interface *current_read = NULL;

    memset(&cmd_line, 0, sizeof(cmd_line));
    /* Leave room for header! */
    cmd_line.buftun_size = sizeof(struct GLAB_MessageHeader);

    while (1) {
        fmax = -1;
        FD_ZERO (&fds_w);
        FD_ZERO (&fds_r);

        /* try to write to child */
        if (NULL != current_read) {
            /*
             * We have a job pending to write to Child's STDIN.
             */
            FD_SET (child_stdin, &fds_w);
            fmax = MAX (fmax, child_stdin);
        }

        /* try to write to TUN device */
        if (NULL != current_write) {
            /*
             * We have a job pending to write to a TUN.
             */
            FD_SET (current_write->fd, &fds_w);
            fmax = MAX (fmax, current_write->fd);
        }
    }
}

void htonMac(struct MacAddress mac, struct MacAddress *target) {
    for (int i = 0; i < MAC_ADDR_SIZE; i++) {
        target->mac[MAC_ADDR_SIZE - i - 1] = mac.mac[i];
    }
}

void prepareRequest(
        struct frame *frame,
        uint16_t interfaceNr,
        struct MacAddress src,
        struct MacAddress dst,
        struct in_addr srcIp,
        struct in_addr dstIp) {
    struct MacAddress empty = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

    struct GLAB_MessageHeader gmh;
    struct EthernetHeader eh;
    struct ArpHeaderEthernetIPv4 ah;
    struct MacAddress srcHton;
    struct MacAddress dstHton;
    htonMac(src, &srcHton);
    htonMac(dst, &dstHton);

    gmh.size = htons((unsigned short int) sizeof(struct frame));
    gmh.type = htons(1); // Todo: dynamically adapt

    eh.src = src;
    eh.dst = dst;
    eh.tag = htons(ETH_P_ARP);

    ah.htype = htons(1);
    ah.ptype = htons(ARP_PTYPE_IPV4);
    ah.hlen = MAC_ADDR_SIZE;
    ah.plen = sizeof(struct in_addr);
    ah.oper = htons(ARP_REQUEST);
    ah.sender_ha = srcHton;
    ah.sender_pa = srcIp;
    ah.target_ha = dstHton;
    ah.target_pa = dstIp;

    memcpy(frame->bytes, &gmh, sizeof(gmh));
    memcpy(&frame->bytes[sizeof(gmh)], &eh, sizeof(eh));
    memcpy(&frame->bytes[sizeof(gmh) + sizeof(eh)], &ah, sizeof(ah));

if(DEBUG) {
    //fprintf(stderr,"len gmh = %lu \nlen eh %lu\nlen ah=%lu\nlen mac = %lu\n", sizeof(struct GLAB_MessageHeader), sizeof(struct EthernetHeader),sizeof(struct ArpHeaderEthernetIPv4),sizeof(struct MacAddress));
    fprintf(stderr, "len gmh = %lu \tlen eh = %lu \tlen ah = %lu \tlen mac = %lu\n", sizeof(gmh),
            sizeof(eh),
            sizeof(ah), sizeof(src));
    debug_print_glab_header(gmh);
    debug_print_ethernet_header(eh);
    debug_print_arp_header(ah);
}
}

/**
 * Launches the arp test.
 *
 * @param argc number of arguments in @a argv
 * @param argv binary name, followed by list of interfaces to switch between
 * @return not really
 */
int main(int argc, char **argv) {
    // TODO do we have to run argv[0]?

    fprintf(stderr, "Test-arp!\n");

    char *ifc4 = "ens4";
    char *ifc5 = "ens5";
    char *ens4 = "ens4[IPV4:192.168.0.1/16]";
    char *ens5 = "ens5[IPV4:10.0.0.3/24]";
    //char *args[] = {argv[1], "ens4[IPV4:192.168.0.1/24]", ens5, NULL};
    char *args[] = {argv[1], "ens4[IPV4:192.168.0.2/24]", NULL};
    //char *args[] = {argv[1], "[", NULL};
    int test = meta(argc, args);

    if (0 != test) {
        fprintf(stderr, "Error during launch of child process!\n");
        return 1;
    }
    fprintf(stderr, "Success!\n");
}


int sendArpRequest() {
    fprintf(stderr, "Send arp request\n");
    struct in_addr *ip1 = (struct in_addr *) malloc(sizeof(struct in_addr));
    struct in_addr *ip2 = (struct in_addr *) malloc(sizeof(struct in_addr));
    inet_pton(AF_INET, "192.168.0.1", &*ip1);
    inet_pton(AF_INET, "192.168.0.2", &*ip2);  // TODO get from args
    struct MacAddress myMac = {{0x01, 0x02, 0x04, 0x08, 0x0F, 0x0A}};
    struct frame frm;
    prepareRequest(&frm, 1, myMac, BROADCAST_MAC, *ip1, *ip2);
    if (DEBUG == 1) {
        /*
        debug_print_mac(BROADCAST_MAC);
        fprintf(stderr, "src ip: ");
        debug_print_ipv4_n(*ip1);
        fprintf(stderr, "dst ip: ");
        debug_print_ipv4_n(*ip2);
        fprintf(stderr, "src mac: ");
        debug_print_mac(myMac);
        fprintf(stderr, "dst mac: ");
        debug_print_mac(BROADCAST_MAC);
         */
    }
    ssize_t write_size = write(child_stdin, &frm.bytes, sizeof(frm));
    if (DEBUG == 1) {
        fprintf(stderr, "%ld write_size\n", write_size);
        debug_print_frame(frm.bytes, write_size);
    }
    //const ssize_t read_size = sizeof(struct frame) * 1;
    uint8_t read_buff[MAX_SIZE];
    ssize_t read_size = read(child_stdout, &read_buff, MAX_SIZE);
    if (DEBUG == 1) {
        fprintf(stderr, "%ld read_size / max_size %ld \n", read_size, MAX_SIZE);
        debug_print_frame(read_buff, read_size);
        fprintf(stderr, "\n");
    }
    // TODO CHECK IF RESPONSE IS CORRECT!
    struct ArpPackage pkg;
    memcpy(&pkg, &read_buff, sizeof(struct ArpPackage));
    if(DEBUG == 1){
        debug_print_glab_header(pkg.gmh);
        debug_print_ethernet_header(pkg.eh);
        debug_print_arp_header(pkg.ah);
    }
}

int meta(int argc, char **argv) {
    int cin[2], cout[2];
    pipe(cin);
    pipe(cout);
    if (0 == (chld = fork())) {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(cin[1]);
        close(cout[0]);
        dup2(cin[0], STDIN_FILENO);
        dup2(cout[1], STDOUT_FILENO);
        execvp(argv[0], argv);
        fprintf(stderr, "Failed to run binary ‘%s’\n", argv[0]);
        exit(1);
    }
    close(cin[0]);
    close(cout[1]);
    child_stdin = cin[1];
    child_stdout = cout[0];
    // send MACs, run test, cleanup

    sendArpRequest();


    // TODO cleanup:
    // Kill child process
    kill(chld, SIGKILL);
}


char *createMessageHeader() {
    //char frame[sizeof(struct EthernetHeader) + sizeof(struct ArpHeaderEthernetIPv4)];
    //struct GLAB_MessageHeader gh;
    //struct EthernetHeader
    //gh.type=1;

}

