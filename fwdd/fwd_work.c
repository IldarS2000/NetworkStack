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
#include "if.h"
#include "arp.h"
#include "icmp.h"
#include "nstk_log.h"

#define NSTK_BURST_SIZE 32

void NSTK_LcoreFwdRun()
{
    NSTK_LOG_INFO("Lcore %u -- forwarding plane", rte_lcore_id());
    uint16_t port = 0;
    RTE_ETH_FOREACH_DEV(port)
    {
        if (rte_eth_dev_socket_id(port) >= 0 && rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {
            NSTK_LOG_WARN("Port %u is on remote NUMA node to polling thread. Performance will not be optimal", port);
        }
    }

    for (;;) {
        RTE_ETH_FOREACH_DEV(port)
        {
            struct rte_mbuf* pkts[NSTK_BURST_SIZE];
            const uint16_t rxNum = rte_eth_rx_burst(port, 0, pkts, NSTK_BURST_SIZE);
            struct rte_mbuf* pkt = pkts[0];

            if (unlikely(rxNum == 0)) {
                continue;
            }

            if (g_ifTbl.ifEntries[port].adminState != NSTK_IF_ADMIN_STATE_UP) {
                rte_pktmbuf_free(pkt);
                continue;
            }

            uint8_t* pktPayload = rte_pktmbuf_mtod(pkt, uint8_t*);
            uint16_t pktLen  = rte_pktmbuf_pkt_len(pkt);
            NSTK_TRACE_MBUF(pktPayload, pktLen);

            int txNum = NSTK_ArpReply(pkts, port);
            txNum += NSTK_IcmpReply(pkts, port);
            if (unlikely(txNum == 0)) {
                rte_pktmbuf_free(pkt);
            }
        }
    }
}