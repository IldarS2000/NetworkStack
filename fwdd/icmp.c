#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "if.h"
#include "nstk_log.h"

int NSTK_IcmpReply(struct rte_mbuf** pkts, uint16_t port)
{
    struct rte_mbuf* pkt = pkts[0];

    struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        return 0;
    }

    if (memcmp(&eth_hdr->dst_addr, &g_ifTbl.ifEntries[port].macAddr, sizeof(struct rte_ether_addr)) != 0) {
        return 0;
    }

    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
    if (ip_hdr->next_proto_id != IPPROTO_ICMP) {
        return 0;
    }

    if (ntohl(ip_hdr->dst_addr) != g_ifTbl.ifEntries[port].ipAddr) {
        return 0;
    }

    struct rte_icmp_hdr* icmp_hdr = (struct rte_icmp_hdr*)((uint8_t*)ip_hdr + sizeof(struct rte_ipv4_hdr));
    if (icmp_hdr->icmp_type != RTE_IP_ICMP_ECHO_REQUEST) {
        return 0;
    }

    struct rte_ether_addr temp_mac;
    rte_ether_addr_copy(&eth_hdr->src_addr, &temp_mac);
    rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
    rte_ether_addr_copy(&temp_mac, &eth_hdr->dst_addr);

    uint32_t temp_ip = ip_hdr->src_addr;
    ip_hdr->src_addr = ip_hdr->dst_addr;
    ip_hdr->dst_addr = temp_ip;
    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

    icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    uint32_t cksum = ~icmp_hdr->icmp_cksum & 0xffff;
    cksum += ~htons(RTE_IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
    cksum += htons(RTE_IP_ICMP_ECHO_REPLY << 8);
    cksum = (cksum & 0xffff) + (cksum >> 16);
    cksum = (cksum & 0xffff) + (cksum >> 16);
    icmp_hdr->icmp_cksum = ~cksum;

    uint16_t txNum = rte_eth_tx_burst(port, 0, &pkt, 1);
    return txNum;
}