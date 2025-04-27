#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#define NSTK_LOG_FILE "/var/log/nstk.log"

void NSTK_WriteLog(const char* level, const char* func, int line, const char* format, ...)
{
    FILE* log_file = fopen(NSTK_LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    time_t now   = time(NULL);
    struct tm* t = localtime(&now);

    fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] [%s:%d] ", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec, level, func, line);

    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fclose(log_file);
}
