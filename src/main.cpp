
#inlude <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_arp.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

#define IP_DEFTTL  64   /* from RFC 1340. */
#define MAX_PORTS 2

static volatile bool force_quit;

/* Basic Ethernet addresses */
struct ether_addr my_eth_addr[MAX_PORTS];
uint32_t my_ip_addr[MAX_PORTS];

/* structure to contains port config */
struct port_conf {
    struct rte_eth_conf eth_conf;
    struct rte_eth_rxconf rx_conf;
    struct rte_eth_txconf tx_conf;
};

/* An array of port configuration */
static struct port_conf port_conf_default = {
    .eth_conf = {
        .rxmode = {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
    },
    .rx_conf = {
        .rx_thresh = {
            .pthresh = 8,   /* Ring prefetch threshold */
            .hthresh = 8,   /* Ring host threshold */
            .wthresh = 4,   /* Ring writeback threshold */
        },
        .rx_free_thresh = 32, /* Free threshold */
    },
    .tx_conf = {
        .tx_thresh = {
            .pthresh = 32,  /* Ring prefetch threshold */
            .hthresh = 0,   /* Ring host threshold */
            .wthresh = 0,   /* Ring writeback threshold */
        },
        .tx_free_thresh = 0, /* Use default values */
        .txq_flags = RTE_ETH_TXQ_FLAGS_NOMULTSEGS |
                RTE_ETH_TXQ_FLAGS_NOOFFLOADS |
                RTE_ETH_TXQ_FLAGS_NO_MBUF_FAST_FREE,
    },
};

static struct rte_mempool *mbuf_pool;

// ARP Cache
#define ARP_TABLE_SIZE 64
struct arp_entry {
    uint32_t ip;
    struct ether_addr mac;
    uint16_t port_id;
    bool valid;
};
struct arp_entry arp_table[ARP_TABLE_SIZE];

// Hash Table for MAC Address Learning
#define MAC_TABLE_SIZE 1024
static struct rte_hash *mac_table = NULL;

struct mac_entry {
    uint16_t port_id;
};

static uint32_t hash_func(const void *key, uint32_t key_len, uint32_t seed) {
    return rte_jhash(key, key_len, seed);
}

// Initialize ARP Table
void init_arp_table() {
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        arp_table[i].valid = false;
    }
}

// Add an entry to the ARP table
void add_arp_entry(uint32_t ip, struct ether_addr mac, uint16_t port_id) {
    // First check if the IP is already in the table
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        if (arp_table[i].valid && arp_table[i].ip == ip) {
            // Update the existing entry
            rte_ether_addr_copy(&mac, &arp_table[i].mac);
            arp_table[i].port_id = port_id;
            return;
        }
    }

    // Find an empty entry
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        if (!arp_table[i].valid) {
            arp_table[i].ip = ip;
            rte_ether_addr_copy(&mac, &arp_table[i].mac);
            arp_table[i].port_id = port_id;
            arp_table[i].valid = true;
            return;
        }
    }
    printf("ARP Table full!\n");
}

// Resolve an IP address to a MAC address from the ARP table
bool resolve_arp(uint32_t ip, struct ether_addr *mac, uint16_t *port_id) {
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        if (arp_table[i].valid && arp_table[i].ip == ip) {
            rte_ether_addr_copy(&arp_table[i].mac, mac);
            *port_id = arp_table[i].port_id;
            return true;
        }
    }
    return false;
}

// Learn MAC address from source address of Ethernet frame
static void learn_mac_address(struct ether_addr *mac_addr, uint16_t port_id) {
    // Check if the MAC address is already in the table
    if (rte_hash_lookup(mac_table, mac_addr) == -ENOENT) {
        // Allocate memory for the MAC entry
        struct mac_entry *entry = rte_malloc(NULL, sizeof(struct mac_entry), 0);
        if (entry == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to allocate memory for MAC entry\n");
        }

        // Set the port ID for the MAC address
        entry->port_id = port_id;

        // Add the MAC address to the table
        if (rte_hash_add_key(mac_table, mac_addr) < 0) {
            rte_free(entry);
            printf("Failed to add MAC address to table\n");
            return;
        }

        // Associate the MAC address with the entry
        rte_hash_set_data(mac_table, mac_addr, entry);

        char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
        rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);
        printf("Learned MAC address %s on port %u\n", mac_str, port_id);
    }
}

// Find port ID for a MAC address
static uint16_t lookup_mac_address(struct ether_addr *mac_addr) {
    struct mac_entry *entry = NULL;
    if (rte_hash_lookup_data(mac_table, mac_addr, (void **)&entry) == 0) {
        return entry->port_id;
    }
    return RTE_MAX_ETHPORTS; // Return an invalid port ID if MAC address is not found
}

// Send ARP request for a specific IP address
static void send_arp_request(uint16_t port_id, uint32_t target_ip) {
    struct rte_mbuf *m;
    struct ether_hdr *eth_hdr;
    struct arp_hdr *arp_hdr;
    char *pkt_data;

    // Allocate mbuf
    m = rte_pktmbuf_alloc(mbuf_pool);
    if (m == NULL) {
        printf("Failed to allocate mbuf for ARP request\n");
        return;
    }

    // Set packet length
    rte_pktmbuf_pkt_len(m) = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
    rte_pktmbuf_data_len(m) = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);

    // Get pointer to packet data
    pkt_data = rte_pktmbuf_mtod(m, char *);

    // Fill Ethernet header
    eth_hdr = (struct ether_hdr *)pkt_data;
    rte_ether_addr_copy(&my_eth_addr[port_id], &eth_hdr->s_addr);
    rte_ether_broadcast(&eth_hdr->d_addr); // Broadcast address
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    // Fill ARP header
    arp_hdr = (struct arp_hdr *)(pkt_data + sizeof(struct ether_hdr));
    arp_hdr->arp_hrd = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_pro = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hln = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_pln = 4; // IPv4 address length
    arp_hdr->arp_op = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
    rte_ether_addr_copy(&my_eth_addr[port_id], (struct ether_addr *)arp_hdr->arp_data);
    *(uint32_t *)(arp_hdr->arp_data + RTE_ETHER_ADDR_LEN) = my_ip_addr[port_id]; // Source IP
    memset(arp_hdr->arp_data + RTE_ETHER_ADDR_LEN + 4, 0, RTE_ETHER_ADDR_LEN); // Target MAC (unknown)
    *(uint32_t *)(arp_hdr->arp_data + RTE_ETHER_ADDR_LEN + 4 + RTE_ETHER_ADDR_LEN) = target_ip; // Target IP

    // Send packet
    int nb_tx = rte_eth_tx_burst(port_id, 0, &m, 1);
    if (nb_tx != 1) {
        printf("Failed to send ARP request\n");
        rte_pktmbuf_free(m);
    } else {
        printf("Sent ARP request for %x on port %u\n", target_ip, port_id);
    }
}

// Handle ARP packets
static void handle_arp(struct rte_mbuf *m, uint16_t port_id) {
    struct ether_hdr *eth_hdr;
    struct arp_hdr *arp_hdr;
    char *pkt_data;

    pkt_data = rte_pktmbuf_mtod(m, char *);
    eth_hdr = (struct ether_hdr *)pkt_data;
    arp_hdr = (struct arp_hdr *)(pkt_data + sizeof(struct ether_hdr));

    uint32_t sender_ip = *(uint32_t *)(arp_hdr->arp_data + RTE_ETHER_ADDR_LEN);
    struct ether_addr sender_mac;
    rte_ether_addr_copy((struct ether_addr *)arp_hdr->arp_data, &sender_mac);

    add_arp_entry(sender_ip, sender_mac, port_id);

    if (rte_be_to_cpu_16(arp_hdr->arp_op) == RTE_ARP_OP_REQUEST) {
        uint32_t target_ip = *(uint32_t *)(arp_hdr->arp_data + RTE_ETHER_ADDR_LEN + 4 + RTE_ETHER_ADDR_LEN);

        if (target_ip == my_ip_addr[port_id]) {
            // Construct ARP response
            arp_hdr->arp_op = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

            // Swap source and destination MAC addresses
            rte_ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
            rte_ether_addr_copy(&my_eth_addr[port_id], &eth_hdr->s_addr);

            // Swap source and destination IP addresses in ARP header
            *(uint32_t *)(arp_hdr->arp_data + RTE_ETHER_ADDR_LEN + 4 + RTE_ETHER_ADDR_LEN) = sender_ip;
            *(uint32_t *)(arp_hdr->arp_data + RTE_ETHER_ADDR_LEN) = my_ip_addr[port_id];

            // Copy our MAC address to the destination MAC address in ARP header
            rte_ether_addr_copy(&my_eth_addr[port_id], (struct ether_addr *)arp_hdr->arp_data);

            // Send the ARP response
            int nb_tx = rte_eth_tx_burst(port_id, 0, &m, 1);
            if (nb_tx != 1) {
                printf("Failed to send ARP response\n");
                rte_pktmbuf_free(m);
            } else {
                printf("Sent ARP response to %x on port %u\n", sender_ip, port_id);
            }
            return;
        }
    }
    rte_pktmbuf_free(m);
}

// Forward IP packets based on destination IP address
static void forward_ip_packet(struct rte_mbuf *m, uint16_t src_port_id) {
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    char *pkt_data;
    struct ether_addr dst_mac;
    uint16_t dst_port_id;
    uint32_t dst_ip;

    pkt_data = rte_pktmbuf_mtod(m, char *);
    eth_hdr = (struct ether_hdr *)pkt_data;
    ip_hdr = (struct ipv4_hdr *)(pkt_data + sizeof(struct ether_hdr));
    dst_ip = ip_hdr->dst_addr;

    if (resolve_arp(dst_ip, &dst_mac, &dst_port_id)) {
        // Found MAC address in ARP table
        rte_ether_addr_copy(&dst_mac, &eth_hdr->d_addr);

        // Learn the source mac on the source port
        learn_mac_address(&eth_hdr->s_addr, src_port_id);

        if(lookup_mac_address(&eth_hdr->d_addr) == src_port_id) {
            // Packet on same port
            rte_pktmbuf_free(m);
        } else {
            // Forward the packet to the destination port
            int nb_tx = rte_eth_tx_burst(dst_port_id, 0, &m, 1);
            if (nb_tx != 1) {
                printf("Failed to forward packet\n");
                rte_pktmbuf_free(m);
            }
        }

    } else {
        // MAC address not found in ARP table, send ARP request
        printf("MAC address not found for IP %x, sending ARP request\n", dst_ip);
        send_arp_request(src_port_id, dst_ip);
        rte_pktmbuf_free(m); // Drop the packet until ARP is resolved
    }
}

/*
 * In this function, we handle packets and send the response.
 */
static void
lcore_main(void)
{
    uint16_t portid;
    int nb_rx;
    unsigned lcore_id;

    lcore_id = rte_lcore_id();
    printf("Starting core %u\n", lcore_id);

    /*
     * Check that the port is on the same NUMA node as the lcore
     * on which the code is running.
     */
    RTE_ETH_FOREACH_DEV(portid) {
        if (rte_eth_dev_socket_id(portid) >= 0 &&
                rte_eth_dev_socket_id(portid) !=
                        (int)rte_socket_id()) {
            printf("WARNING: port %d is on remote NUMA node to "
                    "polling thread.\n\tPerformance will "
                    "not be optimal.\n", portid);
        }

        printf("Core %u: Port %u\n", lcore_id, portid);
    }

    printf("Lcore %u: RX and TX loop\n", lcore_id);

    /* Run until the application is quit or killed. */
    while (!force_quit) {
        RTE_ETH_FOREACH_DEV(portid) {

            /* Get burst of RX packets, from first port of pair. */
            struct rte_mbuf *bufs[32];
            nb_rx = rte_eth_rx_burst(portid, 0,
                        bufs, RTE_DIM(bufs));

            if (unlikely(nb_rx == 0))
                continue;

            for (int i = 0; i < nb_rx; i++) {
                struct rte_mbuf *m = bufs[i];
                struct ether_hdr *eth_hdr;
                char *pkt_data;

                pkt_data = rte_pktmbuf_mtod(m, char *);
                eth_hdr = (struct ether_hdr *)pkt_data;

                uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

                if (ether_type == RTE_ETHER_TYPE_IPV4) {
                    struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(pkt_data + RTE_ETHER_HDR_LEN);
                    if (ip_hdr->protocol == IPPROTO_ICMP) {
                        struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)((char *)ip_hdr + sizeof(struct ipv4_hdr));
                        if (icmp_hdr->type == RTE_ICMP_ECHO_REQUEST) {
                            // Handle ICMP Echo Request
                            rte_ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
                            rte_ether_addr_copy(&my_eth_addr[portid], &eth_hdr->s_addr);

                            uint32_t src_ip = ip_hdr->src_addr;
                            uint32_t dst_ip = ip_hdr->dst_addr;
                            ip_hdr->src_addr = dst_ip;
                            ip_hdr->dst_addr = src_ip;

                            icmp_hdr->type = RTE_ICMP_ECHO_REPLY;

                            icmp_hdr->checksum = 0;
                            icmp_hdr->checksum = rte_ipv4_cksum((const void *)icmp_hdr, rte_be_to_cpu_16(ip_hdr->tot_len) - sizeof(struct ipv4_hdr));

                            ip_hdr->hdr_checksum = 0;
                            ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr, sizeof(struct ipv4_hdr));

                            int nb_tx = rte_eth_tx_burst(portid, 0, &m, 1);
                            if (nb_tx != 1) {
                                printf("Failed to send ICMP Echo Reply\n");
                                rte_pktmbuf_free(m);
                            }
                        } else {
                            rte_pktmbuf_free(m);
                        }
                    } else {
                        forward_ip_packet(m, portid);
                    }
                } else if (ether_type == RTE_ETHER_TYPE_ARP) {
                    handle_arp(m, portid);
                } else {
                    rte_pktmbuf_free(m);
                }
            }
        }
    }
}


static int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf local_port_conf = port_conf_default.eth_conf;
    struct rte_eth_rxconf rxq_conf = port_conf_default.rx_conf;
    struct rte_eth_txconf txq_conf = port_conf_default.tx_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    rte_eth_dev_info_get(port, &dev_info);

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |=
            RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &local_port_conf);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                    rte_eth_dev_socket_id(port),
                    &rxq_conf, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                rte_eth_dev_socket_id(port),
                &txq_conf);
        if (retval < 0)
            return retval;
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Enable promiscuous mode for RX. */
    rte_eth_promiscuous_enable(port);

    /* Get the port MAC address. */
    rte_eth_macaddr_get(port, &my_eth_addr[port]);
    printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
            port,
            my_eth_addr[port].addr_bytes[0],
            my_eth_addr[port].addr_bytes[1],
            my_eth_addr[port].addr_bytes[2],
            my_eth_addr[port].addr_bytes[3],
            my_eth_addr[port].addr_bytes[4],
            my_eth_addr[port].addr_bytes[5]);

    return 0;
}

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
                signum);
        force_quit = true;
    }
}

int
main(int argc, char *argv[])
{
    uint16_t portid;
    unsigned nb_ports;
    unsigned lcore_id;
    char s[64];
    struct rte_hash_params hash_params = {
        .name = "mac_table",
        .entries = MAC_TABLE_SIZE,
        .key_len = RTE_ETHER_ADDR_LEN,
        .hash_func = hash_func,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Count available ports */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
    if (nb_ports > MAX_PORTS)
        rte_exit(EXIT_FAILURE, "Too many Ethernet ports - bye\n");

    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* An Ethernet device is designated by its port ID. */
    RTE_ETH_FOREACH_DEV(portid) {
        /* Initialize the port. */
        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
                    portid);
    }

    if (!rte_eth_dev_is_valid_port(0)) {
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
    }

    // Create hash table
    mac_table = rte_hash_create(&hash_params);
    if (mac_table == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to create MAC address table\n");
    }

    init_arp_table();

    // Configure IP addresses for ports (replace with your actual IPs)
    my_ip_addr[0] = rte_cpu_to_be_32(inet_addr("192.168.1.100")); // Example IP for port 0
    my_ip_addr[1] = rte_cpu_to_be_32(inet_addr("192.168.2.100")); // Example IP for port 1

    printf("Enter IP address for port 0: ");
    if (fgets(s, sizeof(s), stdin) != NULL) {
        s[strcspn(s, "\n")] = 0;
        my_ip_addr[0] = rte_cpu_to_be_32(inet_addr(s));
    }

    printf("Enter IP address for port 1: ");
    if (fgets(s, sizeof(s), stdin) != NULL) {
        s[strcspn(s, "\n")] = 0;
        my_ip_addr[1] = rte_cpu_to_be_32(inet_addr(s));
    }


    /* Launch per-lcore init. */
    rte_eal_mp_lcore_foreach(lcore_main, NULL);

    // Free hash table
    rte_hash_free(mac_table);

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}
