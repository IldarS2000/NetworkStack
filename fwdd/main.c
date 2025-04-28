#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "arp.h"
#include "icmp.h"
#include "nstk_log.h"

#define NSTK_RX_RING_SIZE 1024
#define NSTK_TX_RING_SIZE 1024

#define NSTK_NUM_MBUFS 8191
#define NSTK_MBUF_CACHE_SIZE 250
#define NSTK_BURST_SIZE 32
#define NSTK_LCORE_NUM 1
#define NSTK_MBUF_POOL_NAME "NSTK_MBUF_POOL"

struct rte_ether_addr g_eth1MacAddr = {0};
const uint32_t g_eth1IpAddr         = 3232235522; // 192.168.0.2

static void NSTK_GetInterfaceMac(const char* ifName, struct rte_ether_addr* etherAddr)
{
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, ifName);
    if (ioctl(fd, SIOCGIFHWADDR, &s) == 0) {
        for (int i = 0; i < 6; ++i) {
            etherAddr->addr_bytes[i] = s.ifr_addr.sa_data[i];
        }
    }
}

static int NSTK_PortInit(uint16_t port, struct rte_mempool* mbuf_pool)
{
    struct rte_eth_conf port_conf    = {0};
    const uint16_t rx_rings          = 1;
    const uint16_t tx_rings          = 1;
    uint16_t nb_rxd                  = NSTK_RX_RING_SIZE;
    uint16_t nb_txd                  = NSTK_TX_RING_SIZE;
    uint16_t q                       = 0;
    struct rte_eth_dev_info dev_info = {0};
    struct rte_eth_txconf txconf     = {0};

    if (!rte_eth_dev_is_valid_port(port)) {
        return EXIT_FAILURE;
    }

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    int ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0) {
        NSTK_LOG_ERROR("Error during getting device (port %u) info: %s\n", port, strerror(-ret));
        return ret;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret != 0) {
        return ret;
    }

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (ret != 0) {
        return ret;
    }

    for (q = 0; q < rx_rings; ++q) {
        ret = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (ret < 0) {
            return ret;
        }
    }

    txconf          = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; ++q) {
        ret = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
        if (ret < 0) {
            return ret;
        }
    }

    ret = rte_eth_dev_start(port);
    if (ret < 0) {
        return ret;
    }

    NSTK_GetInterfaceMac("eth1", &g_eth1MacAddr);
    // ret = rte_eth_dev_default_mac_addr_set(port, &g_eth1MacAddr);
    // if (ret != 0) {
    //     return ret;
    // }
    NSTK_LOG_INFO("port %u, mac: %02X:%02X:%02X:%02X:%02X:%02X", port, RTE_ETHER_ADDR_BYTES(&g_eth1MacAddr));

    ret = rte_eth_promiscuous_enable(port);
    if (ret != 0) {
        return ret;
    }

    return EXIT_SUCCESS;
}

static __rte_noreturn void NSTK_LcoreMain(void)
{
    uint16_t port = 0;
    RTE_ETH_FOREACH_DEV(port)
    {
        if (rte_eth_dev_socket_id(port) >= 0 && rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {
            NSTK_LOG_WARN("Port %u is on remote NUMA node to polling thread. Performance will not be optimal", port);
        }
    }
    NSTK_LOG_INFO("Core %u forwarding packets", rte_lcore_id());

    for (;;) {
        RTE_ETH_FOREACH_DEV(port)
        {
            struct rte_mbuf* bufs[NSTK_BURST_SIZE];
            const uint16_t rxNum = rte_eth_rx_burst(port, 0, bufs, NSTK_BURST_SIZE);

            if (unlikely(rxNum == 0)) {
                continue;
            }

            struct rte_mbuf* pkt = bufs[0];
            uint8_t* pkt_data    = rte_pktmbuf_mtod(pkt, uint8_t*);
            uint16_t pkt_len     = rte_pktmbuf_pkt_len(pkt);
            NSTK_LOG_MBUF(pkt_data, pkt_len);

            NSTK_ArpReply(pkt, port, &g_eth1MacAddr, g_eth1IpAddr);
            uint16_t txNum = NSTK_IcmpFastReply(bufs, port);

            if (unlikely(txNum < rxNum)) {
                rte_pktmbuf_free(pkt);
            }
        }
    }
}

int main(int argc, char* argv[])
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        NSTK_LOG_ERROR("Failed to init EAL");
        return EXIT_FAILURE;
    }

    argc -= ret;
    argv += ret;

    uint16_t portNum = rte_eth_dev_count_avail();
    if (portNum == 0) {
        NSTK_LOG_ERROR("Error, there is no ports available", portNum);
        return EXIT_FAILURE;
    }
    NSTK_LOG_INFO("%u ports available", portNum);

    struct rte_mempool* mbuf_pool =
            rte_pktmbuf_pool_create(NSTK_MBUF_POOL_NAME, NSTK_NUM_MBUFS * portNum, NSTK_MBUF_CACHE_SIZE, 0,
                                    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        NSTK_LOG_ERROR("Failed to create mbuf pool");
        return EXIT_FAILURE;
    }

    uint16_t portid = 0;
    RTE_ETH_FOREACH_DEV(portid)
    {
        if (NSTK_PortInit(portid, mbuf_pool) != EXIT_SUCCESS) {
            NSTK_LOG_ERROR("Failed to init port %u", portid);
            return EXIT_FAILURE;
        }
    }

    if (rte_lcore_count() > NSTK_LCORE_NUM) {
        NSTK_LOG_WARN("Too many lcores enabled. Only %u used", NSTK_LCORE_NUM);
    }

    NSTK_LcoreMain();

    rte_eal_cleanup();
    return EXIT_SUCCESS;
}
