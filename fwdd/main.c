#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "ctl_work.h"
#include "fwd_work.h"
#include "arp.h"
#include "icmp.h"
#include "if.h"
#include "nstk_log.h"

int main(int argc, char* argv[])
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        NSTK_LOG_ERROR("Failed to init EAL");
        return EXIT_FAILURE;
    }

    argc -= ret;
    argv += ret;

    const uint16_t portNum = rte_eth_dev_count_avail();
    if (portNum == 0) {
        NSTK_LOG_ERROR("Error, there is no ports available", portNum);
        return EXIT_FAILURE;
    }
    NSTK_LOG_INFO("%u ports available", portNum);

    struct rte_mempool* mbuf_pool =
            rte_pktmbuf_pool_create(NSTK_MBUF_POOL_NAME, NSTK_NUM_MBUFS * portNum, NSTK_MBUF_CACHE_SIZE, 0,
                                    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        NSTK_LOG_ERROR("Failed to create mbuf pool");
        return EXIT_FAILURE;
    }

    if (NSTK_ReadPortConfig() != EXIT_SUCCESS) {
        NSTK_LOG_ERROR("Failed to read port config");
        return EXIT_FAILURE;
    }

    uint16_t portid = 0;
    RTE_ETH_FOREACH_DEV(portid)
    {
        if (NSTK_PortInit(portid, mbuf_pool) != EXIT_SUCCESS) {
            NSTK_LOG_ERROR("Failed to init port %u", portid);
            return EXIT_FAILURE;
        }
    }

    if (rte_lcore_count() > NSTK_LCORE_NUM) {
        NSTK_LOG_WARN("Too many lcores enabled. Only %u used", NSTK_LCORE_NUM);
    }

    rte_eal_remote_launch(NSTK_LcoreCtlRun, NULL, NSTK_CTL_LCORE);
    NSTK_LcoreFwdRun();
    rte_eal_mp_wait_lcore();

    rte_eal_cleanup();
    return EXIT_SUCCESS;
}
