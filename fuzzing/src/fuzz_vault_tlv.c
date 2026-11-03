/*
 * libFuzzer harness for vault_tlv_parse().
 *
 * Feeds arbitrary bytes into the P1=0x00 TLV parser and relies on
 * AddressSanitizer / MemorySanitizer to detect any out-of-bounds access,
 * use of uninitialized data, or integer overflow in the parser or the
 * U4BE / U8BE helpers it calls.
 *
 * No exceptions, no globals, no Ledger SDK calls beyond os_utils.h.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "vault_tlv.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    vault_intent_t out;
    memset(&out, 0, sizeof(out));
    (void) vault_tlv_parse(data, size, &out);
    return 0;
}
