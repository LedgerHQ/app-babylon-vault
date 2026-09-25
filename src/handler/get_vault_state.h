#pragma once

#include "../../bitcoin_app_base/src/boilerplate/dispatcher.h"

/**
 * @brief Handler for GET_VAULT_STATE (INS 0x82) — read-only session query.
 *
 * P1=0x00, P2=0x00, empty CData. Responds SW_OK with
 *   len_i(1B) | intent_fp(len_i B) | len_r(1B) | context_fp(len_r B)
 * where each length is 0 (not held) or 4. See vault_context_encode_state for the
 * fingerprint definitions and docs/apdu.md for the host contract.
 *
 * No user presence, no screen, no state change. A malformed call (P1 or P2 non-zero,
 * non-empty CData) is rejected with a status word and leaves the session untouched.
 *
 * Security: the caller is unauthenticated and needs no approval, so any host may poll this.
 * What it learns is that a session exists and two 4-byte truncated SHA-256 values. The
 * context fingerprint is over a root the host already received from DERIVE_CONTEXT_HASH
 * P2=0x00, and the intent fingerprint over APDUs the host itself sent, so both are only a
 * check value for data the legitimate host holds; neither can be inverted to recover the
 * root or the intent. Accepted in ADR-001, like the unauthenticated caller of Screen 1
 * (Cerberus V-012); see APP_SPECIFICATION.md.
 *
 * @param dc   Dispatcher context.
 * @param cmd  Parsed APDU command.
 */
void handler_get_vault_state(dispatcher_context_t *dc, const command_t *cmd);
