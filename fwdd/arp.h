#ifndef NSTK_ARP_H
#define NSTK_ARP_H

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

int NSTK_ArpReply(struct rte_mbuf** pkts, uint16_t port);

#endif // NSTK_ARP_H