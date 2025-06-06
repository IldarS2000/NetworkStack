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

#include "fwd_work.h"
#include "arp.h"
#include "icmp.h"
#include "if.h"
#include "nstk_log.h"

NSTK_IfEntry g_ifEntryEth1 = {
    .ifName = "eth1",
    .adminState = NSTK_IF_ADMIN_STATE_UP,
    .mtu = NSTK_IF_DEFAULT_MTU
};

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

int NSTK_PortInit(uint16_t port, struct rte_mempool* mbuf_pool)
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

    NSTK_GetInterfaceMac("eth1", &g_ifEntryEth1.macAddr);
    NSTK_LOG_INFO("port %u, mac: %02X:%02X:%02X:%02X:%02X:%02X", port, RTE_ETHER_ADDR_BYTES(&g_ifEntryEth1.macAddr));

    ret = rte_eth_promiscuous_enable(port);
    if (ret != 0) {
        return ret;
    }

    g_ifEntryEth1.portId = port;

    return EXIT_SUCCESS;
}