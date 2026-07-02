#include "derive_context_hash.h"
#include "derive_context_hash_core.h"

#include "../globals.h"
#include "../vault_context.h"
#include "../../bitcoin_app_base/src/boilerplate/sw.h"
#include "../../bitcoin_app_base/src/crypto.h"

#define P1_DERIVE 0x00

// Upper bound on the connected-pubkey derivation path depth (levels).
#define MAX_DERIVATION_PATH_LEN 10u

/* SW for BIP-32 / connected-pubkey derivation failure (mirrors approve handler). */
#define SW_BIP32_FAIL ((uint16_t) 0x6F00)

/**
 * @brief DERIVE_CONTEXT_HASH (INS 0x81) — single-APDU root derivation.
 *
 * P1 = 0x00, CData:
 *   app_name_len (1 B) | app_name (≤64 B)
 *   path_len     (1 B) | path (path_len × 4 B, u32 big-endian)
 *   context      (remaining bytes, non-empty)
 *
 * The device derives the 33-byte compressed connected pubkey at `path`, computes
 *   root = HKDF-SHA256(privkey@m/73681862', "derive-context-hash",
 *                      SHA256(app_name)||SHA256(canonicalNetworkName)||pubkey||context, 32)
 * stores it, advances to HASH_DERIVED, and returns the 32-byte root. The host
 * expands the root into the per-vault secrets (derive-vault-secrets); no preimage
 * is retained or released by the device.
 */
void handler_derive_context_hash(dispatcher_context_t *dc, const command_t *cmd) {
    if (cmd->p1 != P1_DERIVE) {
        SEND_SW(dc, SW_WRONG_P1P2);
        return;
    }

    // Re-deriving cancels any in-flight session.
    if (G_vault_context.state != VAULT_STATE_IDLE) {
        vault_context_invalidate(&G_vault_context);
    }
    explicit_bzero(&G_scratch, sizeof(G_scratch));
    explicit_bzero(&G_approve_intent_state, sizeof(G_approve_intent_state));

    const uint8_t *data = cmd->data;
    const size_t lc = cmd->lc;
    size_t off = 0;

    // app_name_len | app_name
    if (lc < 1u) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    uint8_t app_name_len = data[off++];
    if (app_name_len == 0u || app_name_len > 64u || off + app_name_len > lc) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    const uint8_t *app_name = data + off;
    off += app_name_len;

    // path_len | path (u32 big-endian per level)
    if (off + 1u > lc) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    uint8_t path_len = data[off++];
    if (path_len == 0u || path_len > MAX_DERIVATION_PATH_LEN || off + (size_t) path_len * 4u > lc) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    uint32_t path[MAX_DERIVATION_PATH_LEN];
    for (uint8_t i = 0; i < path_len; i++) {
        path[i] = ((uint32_t) data[off] << 24) | ((uint32_t) data[off + 1] << 16) |
                  ((uint32_t) data[off + 2] << 8) | (uint32_t) data[off + 3];
        off += 4u;
    }

    // context (the remainder) — must be non-empty
    const uint8_t *context = data + off;
    const size_t context_len = lc - off;
    if (context_len == 0u) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // Derive the 33-byte compressed connected public key at the host-supplied path.
    uint8_t connected_pubkey[VAULT_COMPRESSED_PUBKEY_LEN];
    if (crypto_get_compressed_pubkey_at_path(path, path_len, connected_pubkey, NULL) != CX_OK) {
        SEND_SW(dc, SW_BIP32_FAIL);
        return;
    }

    // Compute and store the root.
    bool ok = hkdf_derive_root(app_name,
                               app_name_len,
                               connected_pubkey,
                               context,
                               context_len,
                               G_vault_context.root);
    explicit_bzero(connected_pubkey, sizeof(connected_pubkey));
    if (!ok) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    if (!vault_context_transition(&G_vault_context, VAULT_STATE_IDLE, VAULT_STATE_HASH_DERIVED)) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    // Return the 32-byte root (the host expands it into the per-vault secrets).
    SEND_RESPONSE(dc, G_vault_context.root, VAULT_HASH256_LEN, SW_OK);
}
