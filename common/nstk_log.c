#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#define NSTK_LOG_FILE "/var/log/nstk.log"
#define NSTK_TRACE_FILE "/var/log/nstk_trace.log"

bool g_pktTraceDisable = true;

void NSTK_WriteLog(const char* level, const char* func, int line, const char* format, ...)
{
    FILE* fd = fopen(NSTK_LOG_FILE, "a");
    if (fd == NULL) {
        perror("Failed to open log file");
        return;
    }

    time_t now   = time(NULL);
    struct tm* t = localtime(&now);

    fprintf(fd, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] [%s:%d] ", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec, level, func, line);

    va_list args;
    va_start(args, format);
    vfprintf(fd, format, args);
    va_end(args);

    fprintf(fd, "\n");
    fclose(fd);
}

void NSTK_WriteMbufTrace(const char* level, const char* func, int line, uint8_t* pkt_data, uint16_t pkt_len)
{
    if (g_pktTraceDisable) { 
        return;
    }
    FILE* fd = fopen(NSTK_TRACE_FILE, "a");
    if (fd == NULL) {
        perror("Failed to open log file");
        return;
    }

    time_t now   = time(NULL);
    struct tm* t = localtime(&now);

    fprintf(fd, "[%04d-%02d-%02d %02d:%02d:%02d][%s][%s:%d] ", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec, level, func, line);

    for (uint16_t i = 0; i < pkt_len; ++i) {
        fprintf(fd, "%x", pkt_data[i]);
    }
    fprintf(fd, "\n");

    fclose(fd);
}