#ifndef NSTK_ARP_H
#define NSTK_ARP_H

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

void NSTK_ArpReply(struct rte_mbuf* mbuf, uint16_t port_id, struct rte_ether_addr* selfMacAddr,
                   uint32_t selfIpAddr);

#endif // NSTK_ARP_H