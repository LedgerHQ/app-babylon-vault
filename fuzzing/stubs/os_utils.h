#pragma once

/* Stub for Ledger SDK os_utils.h — used by vault_tlv.c in the fuzz build.
 * Identical to unit-tests/mocks/os_utils.h; kept separate so both build
 * trees remain self-contained. */

#include <stddef.h>
#include <stdint.h>

static inline uint16_t U2BE(const uint8_t *buf, size_t off)
{
    return (uint16_t) ((buf[off] << 8) | buf[off + 1]);
}

static inline uint32_t U4BE(const uint8_t *buf, size_t off)
{
    return ((uint32_t) buf[off]     << 24)
         | ((uint32_t) buf[off + 1] << 16)
         | ((uint32_t) buf[off + 2] <<  8)
         | ((uint32_t) buf[off + 3]);
}

static inline uint64_t U8BE(const uint8_t *buf, size_t off)
{
    return ((uint64_t) buf[off]     << 56)
         | ((uint64_t) buf[off + 1] << 48)
         | ((uint64_t) buf[off + 2] << 40)
         | ((uint64_t) buf[off + 3] << 32)
         | ((uint64_t) buf[off + 4] << 24)
         | ((uint64_t) buf[off + 5] << 16)
         | ((uint64_t) buf[off + 6] <<  8)
         | ((uint64_t) buf[off + 7]);
}
