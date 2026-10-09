#ifndef TEKTON_HASH_H
#define TEKTON_HASH_H

/*
 * edr-tekton :: Hashing Algorithms
 * Multiple hash algorithms for API name resolution.
 * Cat 1.3, 1.5, 1.8, 1.9 from the technique library.
 */

#include "../core/types.h"

/* ── CRC32B (Cat 1.5, 1.8) ───────────────────────────── */

#define CRC32B_POLYNOMIAL  0xEDB88320
#define CRC32B_SEED        0xFFFFFFFF

DWORD TektonHashCrc32b(const BYTE* data, SIZE_T length);
DWORD TektonHashCrc32bStringA(const char* str);
DWORD TektonHashCrc32bStringW(const wchar_t* str);

/* Case-insensitive variant (for DLL name comparison) */
DWORD TektonHashCrc32bStringAi(const char* str);
DWORD TektonHashCrc32bStringWi(const wchar_t* str);

/* ── Djb2 (Cat 1.9, used in sRDI) ────────────────────── */

#define DJB2_SEED  5381

DWORD TektonHashDjb2(const BYTE* data, SIZE_T length);
DWORD TektonHashDjb2StringA(const char* str);

/* ── Additive Hash (Cat 1.3) ──────────────────────────── */

#define ADDITIVE_SEED      0x1F2E3D4C
#define ADDITIVE_MULTIPLIER 0x1003F

DWORD TektonHashAdditive(const char* str);

/* ── Custom Rotating Hash ─────────────────────────────── */

DWORD TektonHashRotate(const char* str, DWORD seed);

/* ── Compile-time hash support ────────────────────────── */

/*
 * For compile-time hash generation, use the companion
 * Python script: tools/hash_gen.py
 *
 * Usage: python hash_gen.py --algo crc32b --func NtAllocateVirtualMemory
 * Output: #define H_NtAllocateVirtualMemory 0xDEADBEEF
 */

#endif /* TEKTON_HASH_H */
