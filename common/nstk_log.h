#ifndef NSTK_LOG_H
#define NSTK_LOG_H

void NSTK_WriteLog(const char* level, const char* func, int line, const char* format, ...);

#define NSTK_LOG_DEBUG(format, ...) NSTK_WriteLog("DEBUG", __func__, __LINE__, format, ##__VA_ARGS__)
#define NSTK_LOG_INFO(format, ...) NSTK_WriteLog("INFO", __func__, __LINE__, format, ##__VA_ARGS__)
#define NSTK_LOG_WARN(format, ...) NSTK_WriteLog("WARN", __func__, __LINE__, format, ##__VA_ARGS__)
#define NSTK_LOG_ERROR(format, ...) NSTK_WriteLog("ERROR", __func__, __LINE__, format, ##__VA_ARGS__)

#endif // NSTK_LOG_H