#ifndef NSTK_CFG_H
#define NSTK_CFG_H

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

#endif // NSTK_CFG_H