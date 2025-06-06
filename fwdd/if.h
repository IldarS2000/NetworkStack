#ifndef NSTK_IF_H
#define NSTK_IF_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_mempool.h>
#include <rte_ether.h>

#define NSTK_RX_RING_SIZE 1024
#define NSTK_TX_RING_SIZE 1024

#define NSTK_NUM_MBUFS 8191
#define NSTK_MBUF_CACHE_SIZE 250
#define NSTK_LCORE_NUM 2
#define NSTK_MBUF_POOL_NAME "NSTK_MBUF_POOL"
#define NSTK_IF_NAME_LEN 32

#define NSTK_IF_ADMIN_STATE_UP 1
#define NSTK_IF_ADMIN_STATE_DOWN 0
#define NSTK_IF_DEFAULT_MTU 1500
#define NSTK_IF_TBL_SIZE 32

typedef struct
{
    uint32_t portId;
    char ifName[NSTK_IF_NAME_LEN];
    uint32_t mtu;
    struct rte_ether_addr macAddr;
    uint32_t ipAddr;
    bool adminState;
} NSTK_IfEntry;

typedef struct
{
    NSTK_IfEntry ifEntries[NSTK_IF_TBL_SIZE];
    size_t size;
} NSTK_IfTbl;

extern NSTK_IfTbl g_ifTbl;

int NSTK_ReadPortConfig();
int NSTK_PortInit(uint16_t port, struct rte_mempool* mbuf_pool);

#endif // NSTK_IF_H