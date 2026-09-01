/*
 * libFuzzer harness for vault_tlv_parse_group().
 *
 * vault_tlv.c contains two independent parsers. fuzz_vault_tlv covers the P1=0x00 scalar
 * payload; this one covers the P1=0x01 group parser, which was previously unreachable from
 * any fuzz target despite being fed host-controlled bytes straight off the wire
 * (APPROVE_VAULT_INTENT, CLA 0xE1 / INS 0x80 / P1=0x01). It implements its own boundary
 * arithmetic, a 32-byte key copy, tag-order tracking, a consumed-length output and
 * back-to-back record framing — none of which the scalar parser exercises.
 *
 * The loop mirrors production framing: handle_group_payload walks one APDU containing
 * several concatenated group records, advancing by the parser's own `consumed` value. That
 * makes `consumed` load-bearing, so it is checked here the way the handler checks it —
 * zero or over-long forward progress is treated as a hard stop rather than trusted.
 *
 * No exceptions, no globals, no Ledger SDK calls beyond os_utils.h.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "vault_constants.h"
#include "vault_tlv.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t pos = 0;
    unsigned int groups = 0;

    /* Production caps a payload at vault_count groups (<= VAULT_MAX_VAULTS); bound the
     * loop the same way so a pathological input cannot spin here instead of in the
     * parser under test. */
    while (pos < size && groups < VAULT_MAX_VAULTS) {
        vault_group_t out;
        size_t consumed = 0;

        memset(&out, 0, sizeof(out));
        vault_tlv_err_t err = vault_tlv_parse_group(data + pos, size - pos, &out, &consumed);
        if (err != VAULT_TLV_OK) break;

        /* A successful parse must make real, in-bounds forward progress. */
        if (consumed == 0 || consumed > size - pos) break;

        pos += consumed;
        groups++;
    }

    return 0;
}
