/*
 * edr-tekton :: Logging Implementation
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "tekton/core/log.h"

static TEKTON_LOG_LEVEL g_log_level = TEKTON_LOG_INFO;

static const char* g_level_names[] = {
    "SILENT", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
};

static const char* g_level_colors[] = {
    "",       "\033[31m", "\033[33m", "\033[36m", "\033[35m", "\033[90m"
};

VOID TektonLogSetLevel(TEKTON_LOG_LEVEL level) {
    g_log_level = level;
}

TEKTON_LOG_LEVEL TektonLogGetLevel(void) {
    return g_log_level;
}

static VOID tekton_log_internal(TEKTON_LOG_LEVEL level, const char* fmt, va_list args) {
    if (level > g_log_level) return;

    fprintf(stderr, "%s[tekton::%s]\033[0m ",
        g_level_colors[level],
        g_level_names[level]);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

VOID TektonLogError(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    tekton_log_internal(TEKTON_LOG_ERROR, fmt, args);
    va_end(args);
}

VOID TektonLogWarn(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    tekton_log_internal(TEKTON_LOG_WARN, fmt, args);
    va_end(args);
}

VOID TektonLogInfo(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    tekton_log_internal(TEKTON_LOG_INFO, fmt, args);
    va_end(args);
}

VOID TektonLogDebug(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    tekton_log_internal(TEKTON_LOG_DEBUG, fmt, args);
    va_end(args);
}

VOID TektonLogTrace(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    tekton_log_internal(TEKTON_LOG_TRACE, fmt, args);
    va_end(args);
}

VOID TektonLogHexDump(
    TEKTON_LOG_LEVEL    level,
    const char*         label,
    const BYTE*         data,
    SIZE_T              length
) {
    if (level > g_log_level) return;
    if (!data || !length) return;

    fprintf(stderr, "%s[tekton::%s]\033[0m %s (%zu bytes):\n",
        g_level_colors[level],
        g_level_names[level],
        label ? label : "hexdump",
        (size_t)length);

    SIZE_T display_len = length > 256 ? 256 : length;

    for (SIZE_T i = 0; i < display_len; i += 16) {
        fprintf(stderr, "  %04zx: ", (size_t)i);

        /* Hex bytes */
        for (SIZE_T j = 0; j < 16; j++) {
            if (i + j < display_len) {
                fprintf(stderr, "%02x ", data[i + j]);
            } else {
                fprintf(stderr, "   ");
            }
            if (j == 7) fprintf(stderr, " ");
        }

        /* ASCII */
        fprintf(stderr, " |");
        for (SIZE_T j = 0; j < 16 && (i + j) < display_len; j++) {
            BYTE c = data[i + j];
            fprintf(stderr, "%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        fprintf(stderr, "|\n");
    }

    if (length > 256) {
        fprintf(stderr, "  ... (%zu more bytes)\n", (size_t)(length - 256));
    }

    fflush(stderr);
}
