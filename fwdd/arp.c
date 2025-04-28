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

#include "nstk_log.h"

void NSTK_ArpReply(struct rte_mbuf* mbuf, uint16_t port_id, struct rte_ether_addr* my_mac_addr, uint32_t my_ip_addr)
{
    struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    struct rte_arp_hdr* arp_hdr   = (struct rte_arp_hdr*)((char*)eth_hdr + sizeof(struct rte_ether_hdr));

    if (arp_hdr->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
        return;
    }

    rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
    rte_ether_addr_copy(my_mac_addr, &eth_hdr->src_addr);

    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    rte_ether_addr_copy(my_mac_addr, &arp_hdr->arp_data.arp_sha);
    arp_hdr->arp_data.arp_sip = rte_cpu_to_be_32(my_ip_addr);
    rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);
    arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;


    uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, &mbuf, 1);
    if (nb_tx == 0) {
        NSTK_LOG_ERROR("failed to transmit arp reply packet");
        rte_pktmbuf_free(mbuf);
    }
}
