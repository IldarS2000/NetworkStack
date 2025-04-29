#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <rte_lcore.h>

#include "nstk_log.h"
#include "nstk_cfg.h"

typedef int (*NSTK_CommandHandler)(char* buff);

typedef struct {
    int module;
    NSTK_CommandHandler handler;
} NSTK_CommandRegistry;

static int NSTK_HandleIpModule(char* buff)
{
    return EXIT_SUCCESS;
}

static int NSTK_HandleIfModule(char* buff)
{
    return EXIT_SUCCESS;
}

static int NSTK_HandleTraceModule(char* buff)
{
    if (buff[1] == NSTK_OPCODE_TRACE_ENABLE) {
        g_pktTraceDisable = false;
    } else if (buff[1] == NSTK_OPCODE_TRACE_DISABLE) {
        g_pktTraceDisable = true;
    }
    return EXIT_SUCCESS;
}

static const NSTK_CommandRegistry g_subModule[] = {{NSTK_MODULE_IP, NSTK_HandleIpModule},
                                                   {NSTK_MODULE_IF, NSTK_HandleIfModule},
                                                   {NSTK_MODULE_TRACE, NSTK_HandleTraceModule}};
static const size_t g_subModuleNum              = sizeof(g_subModule) / sizeof(g_subModule[0]);

int NSTK_ControlPlaneCfgWork(void* arg)
{
    NSTK_LOG_INFO("Lcore %u calculating control plane configuration", rte_lcore_id());
    int serverSock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (serverSock < 0) {
        NSTK_LOG_ERROR("failed to create socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, NSTK_CFG_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    unlink(NSTK_CFG_SOCKET_PATH);
    if (bind(serverSock, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0) {
        NSTK_LOG_ERROR("failed to bind socket");
        close(serverSock);
        return EXIT_FAILURE;
    }

    if (listen(serverSock, 1) < 0) {
        NSTK_LOG_ERROR("failed to listen socket");
        close(serverSock);
        return EXIT_FAILURE;
    }
    NSTK_LOG_INFO("Server is listening on %s", NSTK_CFG_SOCKET_PATH);

    while (true) {
        int clientSock = accept(serverSock, NULL, NULL);
        if (clientSock < 0) {
            NSTK_LOG_ERROR("failed to accept");
            continue;
        }

        char buffer[NSTK_CFG_BUF_SIZE];
        ssize_t bytesRecvNum = recv(clientSock, buffer, sizeof(buffer), 0);
        if (bytesRecvNum < 0) {
            NSTK_LOG_ERROR("failed to recv");
            close(clientSock);
            continue;
        }

        buffer[bytesRecvNum] = '\0';
        for (size_t i = 0; i < g_subModuleNum; ++i) {
            if (buffer[0] == g_subModule[i].module) {
                g_subModule[i].handler(buffer);
            }
        }

        close(clientSock);
    }

    close(serverSock);
    unlink(NSTK_CFG_SOCKET_PATH);
    return EXIT_SUCCESS;
}
