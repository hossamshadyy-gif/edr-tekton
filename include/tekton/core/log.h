#ifndef TEKTON_LOG_H
#define TEKTON_LOG_H

/*
 * edr-tekton :: Logging
 * Operational logging with verbosity control.
 * In release builds, logging compiles to no-ops.
 */

#include "types.h"

typedef enum _TEKTON_LOG_LEVEL {
    TEKTON_LOG_SILENT   = 0,
    TEKTON_LOG_ERROR    = 1,
    TEKTON_LOG_WARN     = 2,
    TEKTON_LOG_INFO     = 3,
    TEKTON_LOG_DEBUG    = 4,
    TEKTON_LOG_TRACE    = 5,
} TEKTON_LOG_LEVEL;

/* Set global log level */
VOID TektonLogSetLevel(TEKTON_LOG_LEVEL level);

/* Get current log level */
TEKTON_LOG_LEVEL TektonLogGetLevel(void);

/* Log functions */
VOID TektonLogError(const char* fmt, ...);
VOID TektonLogWarn(const char* fmt, ...);
VOID TektonLogInfo(const char* fmt, ...);
VOID TektonLogDebug(const char* fmt, ...);
VOID TektonLogTrace(const char* fmt, ...);

/* Convenience macros with file/line info */
#ifdef TEKTON_DEBUG
    #define TLOG_ERROR(fmt, ...) TektonLogError("[%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
    #define TLOG_WARN(fmt, ...)  TektonLogWarn("[%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
    #define TLOG_INFO(fmt, ...)  TektonLogInfo("[%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
    #define TLOG_DEBUG(fmt, ...) TektonLogDebug("[%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
    #define TLOG_TRACE(fmt, ...) TektonLogTrace("[%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
    /* Release: strip debug/trace entirely */
    #define TLOG_ERROR(fmt, ...) TektonLogError(fmt, ##__VA_ARGS__)
    #define TLOG_WARN(fmt, ...)  TektonLogWarn(fmt, ##__VA_ARGS__)
    #define TLOG_INFO(fmt, ...)  TektonLogInfo(fmt, ##__VA_ARGS__)
    #define TLOG_DEBUG(fmt, ...) ((void)0)
    #define TLOG_TRACE(fmt, ...) ((void)0)
#endif

/* Hex dump for debugging payloads */
VOID TektonLogHexDump(
    TEKTON_LOG_LEVEL level,
    const char*      label,
    const BYTE*      data,
    SIZE_T           length
);

#endif /* TEKTON_LOG_H */
