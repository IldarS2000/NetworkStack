#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "nstk_cfg.h"

typedef int (*NSTK_CommandHandler)(int argc, char* argv[]);

typedef struct {
    const char* module;
    NSTK_CommandHandler handler;
} NSTK_CommandRegistry;

static void NSTK_PrintHelp()
{
    printf("Usage:\n");
    printf("  fwdctl ip add x.x.x.x/x DEVICE_NAME\n");
    printf("  fwdctl ip del x.x.x.x/x DEVICE_NAME\n");
    printf("  fwdctl if down DEVICE_NAME\n");
    printf("  fwdctl if up DEVICE_NAME\n");
    printf("  fwdctl trace enable\n");
    printf("  fwdctl trace disable\n");
}

static int NSTK_SendCfgToCp(char* buffer, size_t bufSize)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Failed to create socket\n");
        return EXIT_FAILURE;
    }

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, NSTK_CFG_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0) {
        printf("Failed to connect\n");
        close(sock);
        return EXIT_FAILURE;
    }

    if (send(sock, buffer, bufSize, 0) < 0) {
        printf("Failed to send\n");
        close(sock);
        return EXIT_FAILURE;
    }

    close(sock);
    return EXIT_SUCCESS;
}

static int NSTK_SerializeIpEntry(const NSTK_IpEntryCfg* ipEntry, char* buffer, size_t bufSize)
{
    if (bufSize < sizeof(NSTK_IpEntryCfg)) {
        printf("Buffer too small\n");
        return EXIT_FAILURE;
    }
    memcpy(buffer + 2, ipEntry, sizeof(NSTK_IpEntryCfg));
    return EXIT_SUCCESS;
}

static int NSTK_SerializeIfEntry(const NSTK_IfEntryCfg* ifEntry, char* buffer, size_t bufSize)
{
    if (bufSize < sizeof(NSTK_IfEntryCfg)) {
        printf("Buffer too small\n");
        return EXIT_FAILURE;
    }
    memcpy(buffer + 2, ifEntry, sizeof(NSTK_IfEntryCfg));
    return EXIT_SUCCESS;
}

// TODO add strict checks about arguments
static int NSTK_HandleIpModule(int argc, char* argv[])
{
    NSTK_IpEntryCfg ipEntry        = {0};
    char buffer[NSTK_CFG_BUF_SIZE] = {0};
    buffer[NSTK_MODULE_POS]        = NSTK_MODULE_IP;
    if (strcmp(argv[2], "add") == 0) {
        buffer[NSTK_OPCODE_POS] = NSTK_OPCODE_IP_ADD;
        (void)strcpy(ipEntry.ipAddr, argv[3]);
        (void)strcpy(ipEntry.ifName, argv[4]);
    } else if (strcmp(argv[2], "del") == 0) {
        buffer[NSTK_OPCODE_POS] = NSTK_OPCODE_IP_DEL;
        (void)strcpy(ipEntry.ipAddr, argv[3]);
        (void)strcpy(ipEntry.ifName, argv[4]);
    } else {
        NSTK_PrintHelp();
        return EXIT_FAILURE;
    }
    if (NSTK_SerializeIpEntry(&ipEntry, buffer, NSTK_CFG_BUF_SIZE) != EXIT_SUCCESS) {
        printf("Failed to serialize ip entry\n");
        return EXIT_FAILURE;
    }
    if (NSTK_SendCfgToCp(buffer, NSTK_CFG_BUF_SIZE) != EXIT_SUCCESS) {
        printf("Failed to send ip entry to CP\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

// TODO add strict checks about arguments
static int NSTK_HandleIfModule(int argc, char* argv[])
{
    NSTK_IfEntryCfg ifEntry        = {0};
    char buffer[NSTK_CFG_BUF_SIZE] = {0};
    buffer[NSTK_MODULE_POS]        = NSTK_MODULE_IF;
    if (strcmp(argv[2], "up") == 0) {
        buffer[NSTK_OPCODE_POS] = NSTK_OPCODE_IF_UP;
        (void)strcpy(ifEntry.ifName, argv[3]);
    } else if (strcmp(argv[2], "down") == 0) {
        buffer[NSTK_OPCODE_POS] = NSTK_OPCODE_IF_DOWN;
        (void)strcpy(ifEntry.ifName, argv[3]);
    } else {
        NSTK_PrintHelp();
        return EXIT_FAILURE;
    }
    if (NSTK_SerializeIfEntry(&ifEntry, buffer, NSTK_CFG_BUF_SIZE) != EXIT_SUCCESS) {
        printf("Failed to serialize if entry\n");
        return EXIT_FAILURE;
    }
    if (NSTK_SendCfgToCp(buffer, NSTK_CFG_BUF_SIZE) != EXIT_SUCCESS) {
        printf("Failed to send if entry to CP\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

// TODO add strict checks about arguments
static int NSTK_HandleTraceModule(int argc, char* argv[])
{
    char buffer[NSTK_CFG_BUF_SIZE] = {0};
    buffer[NSTK_MODULE_POS]        = NSTK_MODULE_TRACE;
    if (strcmp(argv[2], "enable") == 0) {
        buffer[NSTK_OPCODE_POS] = NSTK_OPCODE_TRACE_ENABLE;
    } else if (strcmp(argv[2], "disable") == 0) {
        buffer[NSTK_OPCODE_POS] = NSTK_OPCODE_TRACE_DISABLE;
    } else {
        NSTK_PrintHelp();
        return EXIT_FAILURE;
    }
    if (NSTK_SendCfgToCp(buffer, NSTK_CFG_BUF_SIZE) != EXIT_SUCCESS) {
        printf("Failed to send trace entry to CP\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static const NSTK_CommandRegistry g_subModule[] = {{"ip", NSTK_HandleIpModule},
                                                   {"if", NSTK_HandleIfModule},
                                                   {"trace", NSTK_HandleTraceModule}};
static const size_t g_subModuleNum              = sizeof(g_subModule) / sizeof(g_subModule[0]);

int main(int argc, char* argv[])
{
    if (argc < 2) {
        NSTK_PrintHelp();
        return EXIT_FAILURE;
    }
    if (strcmp(argv[1], "help") == 0) {
        NSTK_PrintHelp();
        return 0;
    }

    for (size_t i = 0; i < g_subModuleNum; ++i) {
        if (strcmp(argv[1], g_subModule[i].module) == 0) {
            return g_subModule[i].handler(argc, argv);
        }
    }

    return EXIT_FAILURE;
}
