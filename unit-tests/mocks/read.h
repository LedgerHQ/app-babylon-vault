#pragma once

/* Inline implementations of the SDK's lib_standard_app/read.h for unit tests. */

#include <stddef.h>
#include <stdint.h>

static inline uint16_t read_u16_be(const uint8_t *ptr, size_t offset) {
    return (uint16_t) ((uint16_t) ptr[offset] << 8 | ptr[offset + 1]);
}

static inline uint32_t read_u32_be(const uint8_t *ptr, size_t offset) {
    return (uint32_t) ptr[offset] << 24 | (uint32_t) ptr[offset + 1] << 16 |
           (uint32_t) ptr[offset + 2] << 8 | ptr[offset + 3];
}

static inline uint64_t read_u64_be(const uint8_t *ptr, size_t offset) {
    return (uint64_t) read_u32_be(ptr, offset) << 32 | read_u32_be(ptr, offset + 4);
}

static inline uint16_t read_u16_le(const uint8_t *ptr, size_t offset) {
    return (uint16_t) (ptr[offset] | (uint16_t) ptr[offset + 1] << 8);
}

static inline uint32_t read_u32_le(const uint8_t *ptr, size_t offset) {
    return (uint32_t) ptr[offset] | (uint32_t) ptr[offset + 1] << 8 |
           (uint32_t) ptr[offset + 2] << 16 | (uint32_t) ptr[offset + 3] << 24;
}

static inline uint64_t read_u64_le(const uint8_t *ptr, size_t offset) {
    return (uint64_t) read_u32_le(ptr, offset) | (uint64_t) read_u32_le(ptr, offset + 4) << 32;
}
