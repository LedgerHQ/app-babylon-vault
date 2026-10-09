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
 * It learns that a session exists and two 4-byte truncated SHA-256 values: check values for
 * a root and intent bytes the legitimate host already holds. A host with no approval can
 * still read context_fp for a root it derived silently (DERIVE_CONTEXT_HASH P2=0x01, inputs
 * of its choosing) — 32 bits of a hash of a 256-bit secret, not invertible and not used
 * elsewhere. Accepted in ADR-001, like the unauthenticated caller of Screen 1; see
 * APP_SPECIFICATION.md.
 *
 * @param dc   Dispatcher context.
 * @param cmd  Parsed APDU command.
 */
void handler_get_vault_state(dispatcher_context_t *dc, const command_t *cmd);
