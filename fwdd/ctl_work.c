#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <rte_lcore.h>

#include "if.h"
#include "nstk_log.h"
#include "nstk_cfg.h"

#define NSTK_IP_STR_LEN 16

typedef void (*NSTK_CommandHandler)(char* buff);

typedef struct {
    int module;
    NSTK_CommandHandler handler;
} NSTK_CommandRegistry;

static void NSTK_ExtractIpFromStr(const char *input, char *output, size_t size) {
    char *slashPos = strchr(input, '/');

    if (slashPos) {
        size_t length = slashPos - input; 
        if (length >= size) length = size - 1;
        strncpy(output, input, length);
    } else {
        strncpy(output, input, size - 1); 
    }
}

static void NSTK_ExtractIpDevNameFromStr(const char *input, char *output) {
    const char *iface = strchr(input, '/');
    if (iface != NULL) {
        ++iface;
        while (*iface && (*iface >= '0' && *iface <= '9')) {
            ++iface;
        }
        strncpy(output, iface, NSTK_IF_NAME_LEN - 1); 
    }
}

static void NSTK_ExtractIfStateDevNameFromStr(const char *input, char *output) {
    if (strncmp(input, "up", 2) == 0) {
        strncpy(output, input + 2, NSTK_IF_NAME_LEN - 1); 
    } else if (strncmp(input, "down", 4) == 0) {
        strncpy(output, input + 4, NSTK_IF_NAME_LEN - 1); 
    } 
}

static uint32_t NSTK_IpStrToUint32(const char *ipStr) {
    struct in_addr ip_addr = {0};
    if (inet_pton(AF_INET, ipStr, &ip_addr) != 1) {
        NSTK_LOG_ERROR("Invalid IP address format");
        return 0;
    }
    return ntohl(ip_addr.s_addr);
}

static void NSTK_HandleIpModule(char* buff)
{
    if (buff[NSTK_OPCODE_POS] == NSTK_OPCODE_IP_ADD) {
        char ipStr[NSTK_IP_STR_LEN] = {0};
        NSTK_ExtractIpFromStr(buff + 2, ipStr, NSTK_IP_STR_LEN);
        g_ifTbl.ifEntries[0].ipAddr = NSTK_IpStrToUint32(ipStr);

        // char ifStr[NSTK_IF_NAME_LEN] = {0};
        // NSTK_ExtractIpDevNameFromStr(buff + 2, ifStr);

        // for (size_t port = 0; port <g_ifTbl.size; ++port) {
        //     if (strcmp(g_ifTbl.ifEntries[port].ifName, ifStr) == 0) {
        //         g_ifTbl.ifEntries[port].ipAddr = NSTK_IpStrToUint32(ipStr);
        //     }
        // }
    } else if (buff[NSTK_OPCODE_POS] == NSTK_OPCODE_IP_DEL) {
        g_ifTbl.ifEntries[0].ipAddr = 0;

        // char ifStr[NSTK_IF_NAME_LEN] = {0};
        // NSTK_ExtractIpDevNameFromStr(buff + 2, ifStr);
        
        // for (size_t port = 0; port <g_ifTbl.size; ++port) {
        //     if (strcmp(g_ifTbl.ifEntries[port].ifName, ifStr) == 0) {
        //         g_ifTbl.ifEntries[port].ipAddr = 0;
        //     }
        // }
    }
}

static void NSTK_HandleIfModule(char* buff)
{
    if (buff[NSTK_OPCODE_POS] == NSTK_OPCODE_IF_UP) {
        g_ifTbl.ifEntries[0].adminState = NSTK_IF_ADMIN_STATE_UP;

        // char ifStr[NSTK_IF_NAME_LEN] = {0};
        // NSTK_ExtractIfStateDevNameFromStr(buff + 2, ifStr);

        // for (size_t port = 0; port <g_ifTbl.size; ++port) {
        //     if (strcmp(g_ifTbl.ifEntries[port].ifName, ifStr) == 0) {
        //         g_ifTbl.ifEntries[port].adminState = NSTK_IF_ADMIN_STATE_UP;
        //     }
        // }
    } else if (buff[NSTK_OPCODE_POS] == NSTK_OPCODE_IF_DOWN) {
        g_ifTbl.ifEntries[0].adminState = NSTK_IF_ADMIN_STATE_DOWN;
        
        // char ifStr[NSTK_IF_NAME_LEN] = {0};
        // NSTK_ExtractIfStateDevNameFromStr(buff + 2, ifStr);

        // for (size_t port = 0; port <g_ifTbl.size; ++port) {
        //     if (strcmp(g_ifTbl.ifEntries[port].ifName, ifStr) == 0) {
        //         g_ifTbl.ifEntries[port].adminState = NSTK_IF_ADMIN_STATE_DOWN;
        //     }
        // }
    }
}

static void NSTK_HandleTraceModule(char* buff)
{
    if (buff[NSTK_OPCODE_POS] == NSTK_OPCODE_TRACE_ENABLE) {
        g_pktTraceDisable = false;
    } else if (buff[NSTK_OPCODE_POS] == NSTK_OPCODE_TRACE_DISABLE) {
        g_pktTraceDisable = true;
    }
}

static const NSTK_CommandRegistry g_subModule[] = {{NSTK_MODULE_IP, NSTK_HandleIpModule},
                                                   {NSTK_MODULE_IF, NSTK_HandleIfModule},
                                                   {NSTK_MODULE_TRACE, NSTK_HandleTraceModule}};
static const size_t g_subModuleNum              = sizeof(g_subModule) / sizeof(g_subModule[0]);

int NSTK_LcoreCtlRun(void* arg)
{
    NSTK_LOG_INFO("Lcore %u -- control plane", rte_lcore_id());
    int serverSock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (serverSock < 0) {
        NSTK_LOG_ERROR("Failed to create socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, NSTK_CFG_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    unlink(NSTK_CFG_SOCKET_PATH);
    if (bind(serverSock, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0) {
        NSTK_LOG_ERROR("Failed to bind socket");
        close(serverSock);
        return EXIT_FAILURE;
    }

    if (listen(serverSock, 1) < 0) {
        NSTK_LOG_ERROR("Failed to listen socket");
        close(serverSock);
        return EXIT_FAILURE;
    }
    NSTK_LOG_INFO("Server is listening on %s", NSTK_CFG_SOCKET_PATH);

    while (true) {
        int clientSock = accept(serverSock, NULL, NULL);
        if (clientSock < 0) {
            NSTK_LOG_ERROR("Failed to accept");
            continue;
        }

        char buffer[NSTK_CFG_BUF_SIZE];
        ssize_t bytesRecvNum = recv(clientSock, buffer, sizeof(buffer), 0);
        if (bytesRecvNum < 0) {
            NSTK_LOG_ERROR("Failed to recv");
            close(clientSock);
            continue;
        }

        buffer[bytesRecvNum] = '\0';
        for (size_t i = 0; i < g_subModuleNum; ++i) {
            if (buffer[NSTK_MODULE_POS] == g_subModule[i].module) {
                g_subModule[i].handler(buffer);
            }
        }

        close(clientSock);
    }

    close(serverSock);
    unlink(NSTK_CFG_SOCKET_PATH);
    return EXIT_SUCCESS;
}
