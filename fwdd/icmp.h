#ifndef NCTK_ICMP_H
#define NCTK_ICMP_H

#include <stdint.h>
#include <rte_mbuf.h>

uint16_t NSTK_IcmpFastReply(struct rte_mbuf** pkts, uint16_t port_id);

#endif // NCTK_ICMP_H