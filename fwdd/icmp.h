#ifndef NSTK_ICMP_H
#define NSTK_ICMP_H

#include <stdint.h>
#include <rte_mbuf.h>

void NSTK_IcmpFastReply(struct rte_mbuf** pkts, uint16_t port_id);

#endif // NSTK_ICMP_H