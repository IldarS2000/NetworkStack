#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>

#include "if.h"
#include "nstk_log.h"

int NSTK_ArpReply(struct rte_mbuf** pkts, uint16_t port)
{
    struct rte_mbuf* pkt = pkts[0];

    struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
    struct rte_arp_hdr* arp_hdr   = (struct rte_arp_hdr*)((char*)eth_hdr + sizeof(struct rte_ether_hdr));

    if (arp_hdr->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
        return 0;
    }

    if (ntohl(arp_hdr->arp_data.arp_tip) != g_ifTbl.ifEntries[port].ipAddr) {
        return 0;
    }

    rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
    rte_ether_addr_copy(&g_ifTbl.ifEntries[port].macAddr, &eth_hdr->src_addr);

    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    rte_ether_addr_copy(&g_ifTbl.ifEntries[port].macAddr, &arp_hdr->arp_data.arp_sha);
    arp_hdr->arp_data.arp_sip = rte_cpu_to_be_32(g_ifTbl.ifEntries[port].ipAddr);
    rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);
    arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;

    uint16_t txNum = rte_eth_tx_burst(port, 0, &pkt, 1);
    return txNum;
}
