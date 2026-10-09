/*
 * edr-tekton :: Hashing Algorithms
 * CRC32B, Djb2, Additive for API name resolution.
 */

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "tekton/util/hash.h"

/* ── CRC32B ───────────────────────────────────────────── */

DWORD TektonHashCrc32b(const BYTE* data, SIZE_T length) {
    DWORD crc = CRC32B_SEED;

    for (SIZE_T i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ CRC32B_POLYNOMIAL;
            } else {
                crc >>= 1;
            }
        }
    }

    return ~crc;
}

DWORD TektonHashCrc32bStringA(const char* str) {
    if (!str) return 0;
    return TektonHashCrc32b((const BYTE*)str, strlen(str));
}

DWORD TektonHashCrc32bStringW(const wchar_t* str) {
    if (!str) return 0;
    SIZE_T len = 0;
    const wchar_t* p = str;
    while (*p++) len++;
    return TektonHashCrc32b((const BYTE*)str, len * sizeof(wchar_t));
}

DWORD TektonHashCrc32bStringAi(const char* str) {
    if (!str) return 0;

    DWORD crc = CRC32B_SEED;

    while (*str) {
        BYTE c = (BYTE)tolower((unsigned char)*str);
        crc ^= c;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ CRC32B_POLYNOMIAL;
            } else {
                crc >>= 1;
            }
        }
        str++;
    }

    return ~crc;
}

DWORD TektonHashCrc32bStringWi(const wchar_t* str) {
    if (!str) return 0;

    DWORD crc = CRC32B_SEED;

    while (*str) {
        /* Convert wide char to lowercase, hash both bytes */
        wchar_t c = (*str >= L'A' && *str <= L'Z') ? (*str + 32) : *str;
        BYTE low = (BYTE)(c & 0xFF);
        BYTE high = (BYTE)((c >> 8) & 0xFF);

        BYTE bytes[2] = { low, high };
        for (int b = 0; b < 2; b++) {
            crc ^= bytes[b];
            for (int j = 0; j < 8; j++) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ CRC32B_POLYNOMIAL;
                } else {
                    crc >>= 1;
                }
            }
        }
        str++;
    }

    return ~crc;
}

/* ── Djb2 ─────────────────────────────────────────────── */

DWORD TektonHashDjb2(const BYTE* data, SIZE_T length) {
    DWORD hash = DJB2_SEED;
    for (SIZE_T i = 0; i < length; i++) {
        hash = ((hash << 5) + hash) + data[i]; /* hash * 33 + c */
    }
    return hash;
}

DWORD TektonHashDjb2StringA(const char* str) {
    if (!str) return 0;
    return TektonHashDjb2((const BYTE*)str, strlen(str));
}

/* ── Additive Hash ────────────────────────────────────── */

DWORD TektonHashAdditive(const char* str) {
    if (!str) return 0;

    DWORD hash = ADDITIVE_SEED;
    while (*str) {
        hash *= ADDITIVE_MULTIPLIER;
        hash += (BYTE)*str;
        hash ^= (hash >> 11);
        str++;
    }
    return hash;
}

/* ── Rotating Hash ────────────────────────────────────── */

DWORD TektonHashRotate(const char* str, DWORD seed) {
    if (!str) return 0;

    DWORD hash = seed;
    while (*str) {
        hash = (hash << 7) | (hash >> 25);
        hash += (BYTE)*str;
        str++;
    }
    return hash;
}
