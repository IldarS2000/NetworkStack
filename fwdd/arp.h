#ifndef NCTK_ARP_H
#define NCTK_ARP_H

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

void NSTK_ArpReply(struct rte_mbuf* request_mbuf, uint16_t port_id, struct rte_ether_addr* my_mac_addr,
                   uint32_t my_ip_addr);

#endif // NCTK_ARP_H