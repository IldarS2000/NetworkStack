#ifndef NSTK_LOG_H
#define NSTK_LOG_H

extern bool g_pktTraceDisable;

void NSTK_WriteLog(const char* level, const char* func, int line, const char* format, ...);
void NSTK_WriteMbufTrace(const char* level, const char* func, int line, uint8_t* pkt_data, uint16_t pkt_len);

#define NSTK_LOG_DEBUG(format, ...) NSTK_WriteLog("DEBUG", __func__, __LINE__, format, ##__VA_ARGS__)
#define NSTK_LOG_INFO(format, ...) NSTK_WriteLog("INFO", __func__, __LINE__, format, ##__VA_ARGS__)
#define NSTK_LOG_WARN(format, ...) NSTK_WriteLog("WARN", __func__, __LINE__, format, ##__VA_ARGS__)
#define NSTK_LOG_ERROR(format, ...) NSTK_WriteLog("ERROR", __func__, __LINE__, format, ##__VA_ARGS__)

#define NSTK_TRACE_MBUF(pkt_data, pkt_len) NSTK_WriteMbufTrace("TRACE", __func__, __LINE__, pkt_data, pkt_len)

#endif // NSTK_LOG_H