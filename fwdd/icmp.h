#ifndef NSTK_ICMP_H
#define NSTK_ICMP_H

#include <stdint.h>
#include <rte_mbuf.h>

int NSTK_IcmpReply(struct rte_mbuf** pkts, uint16_t port);

#endif // NSTK_ICMP_H