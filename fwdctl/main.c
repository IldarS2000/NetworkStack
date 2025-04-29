#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define NSTK_CFG_SOCKET_PATH "/tmp/nstk_cfg_socket"
#define NSTK_IP_LEN 32
#define NSTK_IF_NAME_LEN 32
#define NSTK_CFG_BUF_SIZE 128

enum
{
    NSTK_MODULE_IP,
    NSTK_MODULE_IF,
    NSTK_MODULE_TRACE,
} NSTK_Module;

enum
{
    NSTK_OPCODE_IP_ADD,
    NSTK_OPCODE_IP_DEL,
    NSTK_OPCODE_IF_UP,
    NSTK_OPCODE_IF_DOWN,
    NSTK_OPCODE_TRACE_ENABLE,
    NSTK_OPCODE_TRACE_DISABLE,
} NSTK_ModuleOpcode;

typedef struct {
    char ipAddr[NSTK_IP_LEN];
    char ifName[NSTK_IF_NAME_LEN];
} NSTK_IpEntry;

typedef struct {
    char ifName[NSTK_IF_NAME_LEN];
} NSTK_IfEntry;

typedef int (*NSTK_CommandHandler)(int argc, char* argv[]);

typedef struct {
    const char* module;
    NSTK_CommandHandler handler;
} NSTK_CommandRegistry;

void NSTK_PrintHelp()
{
    printf("Usage:\n");
    printf("  nstk ip add x.x.x.x/x DEVICE_NAME\n");
    printf("  nstk ip del x.x.x.x/x DEVICE_NAME\n");
    printf("  nstk if down DEVICE_NAME\n");
    printf("  nstk if up DEVICE_NAME\n");
    printf("  nstk trace enable\n");
    printf("  nstk trace disable\n");
}

int NSTK_SendCfgToCp(char* buffer, size_t bufSize)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("failed to create socket\n");
        return EXIT_FAILURE;
    }

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, NSTK_CFG_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0) {
        printf("failed to connect\n");
        close(sock);
        return EXIT_FAILURE;
    }

    if (send(sock, buffer, bufSize, 0) < 0) {
        printf("failed to send\n");
        close(sock);
        return EXIT_FAILURE;
    }

    close(sock);
    return EXIT_SUCCESS;
}

int NSTK_SerializeIpEntry(const NSTK_IpEntry* ipEntry, char* buffer, size_t bufSize)
{
    if (bufSize < sizeof(NSTK_IpEntry)) {
        printf("Buffer too small\n");
        return EXIT_FAILURE;
    }
    memcpy(buffer + 2, ipEntry, sizeof(NSTK_IpEntry));
    return EXIT_SUCCESS;
}

int NSTK_SerializeIfEntry(const NSTK_IfEntry* ifEntry, char* buffer, size_t bufSize)
{
    if (bufSize < sizeof(NSTK_IfEntry)) {
        printf("Buffer too small\n");
        return EXIT_FAILURE;
    }
    memcpy(buffer + 2, ifEntry, sizeof(NSTK_IfEntry));
    return EXIT_SUCCESS;
}

// TODO add strict checks about arguments
int NSTK_HandleIpModule(int argc, char* argv[])
{
    NSTK_IpEntry ipEntry           = {0};
    char buffer[NSTK_CFG_BUF_SIZE] = {0};
    buffer[0]                      = NSTK_MODULE_IP;
    if (strcmp(argv[2], "add") == 0) {
        buffer[1] = NSTK_OPCODE_IP_ADD;
        (void)strcpy(ipEntry.ipAddr, argv[3]);
        (void)strcpy(ipEntry.ifName, argv[4]);
    } else if (strcmp(argv[2], "del") == 0) {
        buffer[1] = NSTK_OPCODE_IP_DEL;
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
int NSTK_HandleIfModule(int argc, char* argv[])
{
    NSTK_IfEntry ifEntry           = {0};
    char buffer[NSTK_CFG_BUF_SIZE] = {0};
    buffer[0]                      = NSTK_MODULE_IF;
    if (strcmp(argv[2], "up") == 0) {
        buffer[1] = NSTK_OPCODE_IF_UP;
        (void)strcpy(ifEntry.ifName, argv[3]);
    } else if (strcmp(argv[2], "down") == 0) {
        buffer[1] = NSTK_OPCODE_IF_DOWN;
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
int NSTK_HandleTraceModule(int argc, char* argv[])
{
    char buffer[NSTK_CFG_BUF_SIZE] = {0};
    buffer[0]                      = NSTK_MODULE_TRACE;
    if (strcmp(argv[2], "enable") == 0) {
        buffer[1] = NSTK_OPCODE_TRACE_ENABLE;
    } else if (strcmp(argv[2], "disable") == 0) {
        buffer[1] = NSTK_OPCODE_TRACE_DISABLE;
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

NSTK_CommandRegistry g_subModule[] = {{"ip", NSTK_HandleIpModule},
                                      {"if", NSTK_HandleIfModule},
                                      {"trace", NSTK_HandleTraceModule}};
const size_t g_subModuleNum        = sizeof(g_subModule) / sizeof(g_subModule[0]);

int main(int argc, char* argv[])
{
    if (argc < 2) {
        NSTK_PrintHelp();
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < g_subModuleNum; ++i) {
        if (strcmp(argv[1], g_subModule[i].module) == 0) {
            return g_subModule[i].handler(argc, argv);
        }
    }

    return EXIT_FAILURE;
}
