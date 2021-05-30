
#ifndef GLAB_IPC_H
#define GLAB_IPC_H

#define _GNU_SOURCE
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <byteswap.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#ifndef ETH_P_ARP
/**
 * Number for ARP
 */
#define ETH_P_ARP 0x0806
#endif

#ifndef ARP_REQUEST
/**
 * Operation of Arp
 */
#define ARP_REQUEST 0x0001
#endif

#ifndef ARP_REPLY
/**
 * Operation of Arp
 */
#define ARP_REPLY 0x0002
#endif

#ifndef ARP_PTYPE_IPV4
/**
 * Protocol type of ARP with IPV4
 */
#define ARP_PTYPE_IPV4 0x0800
#endif

/**
 * gcc 4.x-ism to pack structures (to be used before structs);
 * Using this still causes structs to be unaligned on the stack on Sparc
 * (See #670578 from Debian).
 */
_Pragma("pack(push)") _Pragma("pack(1)")
/**
 * Header for all communications between components.
 */
struct GLAB_MessageHeader
{

    /**
     * The length of the struct (in bytes, including the length field itself),
     * in big-endian format.
     */
    uint16_t size;

    /**
     * The type of the message. 0 for 'control' (commands, feedback for
     * user), otherwise packets received from or to be sent to an
     * adapter. The first control message includes the list of all MAC
     * addresses in the body. In all other cases, type is used to
     * specify the number of the adapter (counting from 1).
     */
    uint16_t type;

};

/**
 * Number of bytes in a MAC.
 */
#define MAC_ADDR_SIZE 6


/**
 * A MAC Address.
 */
struct MacAddress
{
    uint8_t mac[MAC_ADDR_SIZE];
};

struct EthernetHeader
{
    struct MacAddress dst;
    struct MacAddress src;

    /**
     * See ETH_P-values.
     */
    uint16_t tag;
};

/**
 * ARP header for Ethernet-IPv4.
 */
struct ArpHeaderEthernetIPv4
{
    /**
     * Must be #ARP_HTYPE_ETHERNET.
     */
    uint16_t htype;

    /**
     * Protocol type, must be #ARP_PTYPE_IPV4
     */
    uint16_t ptype;

    /**
     * HLEN.  Must be #MAC_ADDR_SIZE.
     */
    uint8_t hlen;

    /**
     * PLEN.  Must be sizeof (struct in_addr) (aka 4).
     */
    uint8_t plen;

    /**
     * Type of the operation.
     */
    uint16_t oper;

    /**
     * HW address of sender. We only support Ethernet.
     */
    struct MacAddress sender_ha;

    /**
     * Layer3-address of sender. We only support IPv4.
     */
    struct in_addr sender_pa;

    /**
     * HW address of target. We only support Ethernet.
     */
    struct MacAddress target_ha;

    /**
     * Layer3-address of target. We only support IPv4.
     */
    struct in_addr target_pa;
};

/**
 * SIZE of Frame bytes
 */
#define FRAME_SIZE sizeof(struct GLAB_MessageHeader) +sizeof(struct EthernetHeader) + sizeof(struct ArpHeaderEthernetIPv4)

struct frame{
    //uint8_t bytes[ETH_FRAME_LEN];
    uint8_t bytes[FRAME_SIZE];
};

struct ArpPacket{
    struct GLAB_MessageHeader gmh;
    struct EthernetHeader eh;
    struct ArpHeaderEthernetIPv4 ah;
};

struct FirstMacs{
    struct GLAB_MessageHeader gmh;
    struct MacAddress mac1;
    //struct MacAddress mac2;
    //struct MacAddress *mac[2]; // TODO change 2 4
};

struct ArpCommand{
    struct GLAB_MessageHeader gmh;
    char *cmd;
};

_Pragma("pack(pop)")

static const struct MacAddress BROADCAST_MAC = {{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}};

static const struct MacAddress EMPTY_MAC = {{0x00,0x00,0x00,0x00,0x00,0x00}};
/**
 * STDIN of child process (to be written to).
 */
static int child_stdin;

/**
 * STDOUT of child process (to be read from).
 */
static int child_stdout;

/**
 * Child PID
 */
static pid_t chld;

#endif