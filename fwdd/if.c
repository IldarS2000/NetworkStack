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
#include "cJSON.h"

#include "fwd_work.h"
#include "arp.h"
#include "icmp.h"
#include "if.h"
#include "nstk_log.h"

#define NSTK_PORT_CFG_JSON "/run/nstk/port_cfg.json"
#define NSTK_PORT_CFG_FIELD_PORTID "portId"
#define NSTK_PORT_CFG_FIELD_IFNAME "ifName"
#define NSTK_PORT_CFG_FIELD_MTU "mtu"
#define NSTK_PORT_CFG_FIELD_IP_ADDR "ipAddr"
#define NSTK_PORT_CFG_FIELD_ADMIN_STATE "adminState"
#define NSTK_PORT_CFG_FIELD_MAC_ADDR "macAddr"

NSTK_IfTbl g_ifTbl = {0};

static bool NSTK_ParseMacStr(const char* mac_str, struct rte_ether_addr* mac)
{
    return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac->addr_bytes[0], &mac->addr_bytes[1],
                  &mac->addr_bytes[2], &mac->addr_bytes[3], &mac->addr_bytes[4], &mac->addr_bytes[5]) == 6;
}

static void NSTK_PrintPortCfgEntry(const NSTK_IfEntry* entry)
{
    NSTK_LOG_INFO("-------------");
    NSTK_LOG_INFO("Port ID: %u", entry->portId);
    NSTK_LOG_INFO("Interface Name: %s", entry->ifName);
    NSTK_LOG_INFO("MTU: %u\n", entry->mtu);
    NSTK_LOG_INFO("MAC: %02X:%02X:%02X:%02X:%02X:%02X", entry->macAddr.addr_bytes[0], entry->macAddr.addr_bytes[1],
                  entry->macAddr.addr_bytes[2], entry->macAddr.addr_bytes[3], entry->macAddr.addr_bytes[4],
                  entry->macAddr.addr_bytes[5]);
    NSTK_LOG_INFO("IPv4 Address: %u", entry->ipAddr);
    NSTK_LOG_INFO("Admin State: %s", entry->adminState ? "Up" : "Down");
    NSTK_LOG_INFO("-------------");
}

static int NSTK_ParsePortCfgJson(const char* jsonStr)
{
    cJSON* root = cJSON_Parse(jsonStr);
    if (!root || !cJSON_IsArray(root)) {
        NSTK_LOG_ERROR("Invalid json format of file: %s", NSTK_PORT_CFG_JSON);
        return EXIT_FAILURE;
    }

    int count = cJSON_GetArraySize(root);
    for (int portId = 0; portId < count && portId < NSTK_IF_TBL_SIZE; ++portId) {
        ++g_ifTbl.size;
        cJSON* item = cJSON_GetArrayItem(root, portId);

        g_ifTbl.ifEntries[portId].portId = cJSON_GetObjectItem(item, NSTK_PORT_CFG_FIELD_PORTID)->valueint;
        strncpy(g_ifTbl.ifEntries[portId].ifName, cJSON_GetObjectItem(item, NSTK_PORT_CFG_FIELD_IFNAME)->valuestring,
                NSTK_IF_NAME_LEN - 1);
        g_ifTbl.ifEntries[portId].ifName[NSTK_IF_NAME_LEN - 1] = '\0';
        g_ifTbl.ifEntries[portId].mtu        = cJSON_GetObjectItem(item, NSTK_PORT_CFG_FIELD_MTU)->valueint;
        g_ifTbl.ifEntries[portId].ipAddr     = cJSON_GetObjectItem(item, NSTK_PORT_CFG_FIELD_IP_ADDR)->valueint;
        g_ifTbl.ifEntries[portId].adminState = cJSON_GetObjectItem(item, NSTK_PORT_CFG_FIELD_ADMIN_STATE)->valueint;

        const char* mac_str = cJSON_GetObjectItem(item, NSTK_PORT_CFG_FIELD_MAC_ADDR)->valuestring;
        if (!NSTK_ParseMacStr(mac_str, &g_ifTbl.ifEntries[portId].macAddr)) {
            NSTK_LOG_ERROR("Invalid MAC address format");
            continue;
        }

        NSTK_PrintPortCfgEntry(&g_ifTbl.ifEntries[portId]);
    }

    cJSON_Delete(root);
    return EXIT_SUCCESS;
}


int NSTK_ReadPortConfig()
{
    FILE* file = fopen(NSTK_PORT_CFG_JSON, "r");
    if (file == NULL) {
        NSTK_LOG_ERROR("Failed to open file: %s", NSTK_PORT_CFG_JSON);
        return EXIT_FAILURE;
    }

    fseek(file, 0, SEEK_END);
    const size_t len = ftell(file);
    rewind(file);

    char* jsonStr = malloc(len + 1);
    (void)fread(jsonStr, 1, len, file);
    jsonStr[len] = '\0';
    fclose(file);

    if (NSTK_ParsePortCfgJson(jsonStr) != EXIT_SUCCESS) {
        NSTK_LOG_ERROR("Failed to parse port cfg");
        return EXIT_FAILURE;
    }

    free(jsonStr);
    return EXIT_SUCCESS;
}

static void NSTK_GetInterfaceMac(const char* ifName, struct rte_ether_addr* etherAddr)
{
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, ifName);
    if (ioctl(fd, SIOCGIFHWADDR, &s) == 0) {
        for (int i = 0; i < 6; ++i) {
            etherAddr->addr_bytes[i] = s.ifr_addr.sa_data[i];
        }
    }
}

int NSTK_PortInit(uint16_t port, struct rte_mempool* mbuf_pool)
{
    struct rte_eth_conf port_conf    = {0};
    const uint16_t rx_rings          = 1;
    const uint16_t tx_rings          = 1;
    uint16_t nb_rxd                  = NSTK_RX_RING_SIZE;
    uint16_t nb_txd                  = NSTK_TX_RING_SIZE;
    uint16_t q                       = 0;
    struct rte_eth_dev_info dev_info = {0};
    struct rte_eth_txconf txconf     = {0};

    if (!rte_eth_dev_is_valid_port(port)) {
        return EXIT_FAILURE;
    }
    g_ifTbl.ifEntries[port].portId = port;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    int ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0) {
        NSTK_LOG_ERROR("Error during getting device (port %u) info: %s", port, strerror(-ret));
        return ret;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret != 0) {
        return ret;
    }

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (ret != 0) {
        return ret;
    }

    for (q = 0; q < rx_rings; ++q) {
        ret = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (ret < 0) {
            return ret;
        }
    }

    txconf          = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; ++q) {
        ret = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
        if (ret < 0) {
            return ret;
        }
    }

    ret = rte_eth_dev_start(port);
    if (ret < 0) {
        return ret;
    }

    NSTK_GetInterfaceMac(g_ifTbl.ifEntries[port].ifName, &g_ifTbl.ifEntries[port].macAddr);
    NSTK_LOG_INFO("port %u, mac: %02X:%02X:%02X:%02X:%02X:%02X", port,
                  RTE_ETHER_ADDR_BYTES(&g_ifTbl.ifEntries[port].macAddr));

    ret = rte_eth_promiscuous_enable(port);
    if (ret != 0) {
        return ret;
    }

    return EXIT_SUCCESS;
}
