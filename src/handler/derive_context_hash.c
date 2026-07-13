#include "derive_context_hash.h"
#include "derive_context_hash_core.h"

#include "../display.h"
#include "../globals.h"
#include "../vault_context.h"
#include "../../bitcoin_app_base/src/boilerplate/sw.h"
#include "../../bitcoin_app_base/src/crypto.h"

#define P1_DERIVE 0x00

/* SW for BIP-32 / connected-pubkey derivation failure (mirrors approve handler). */
#define SW_BIP32_FAIL ((uint16_t) 0x6F00)

/**
 * @brief DERIVE_CONTEXT_HASH (INS 0x81) — single-APDU root derivation.
 *
 * P1 = 0x00, CData:
 *   app_name_len (1 B) | app_name (≤VAULT_APP_NAME_MAX_LEN B)
 *   path_len     (1 B) | path (path_len × 4 B, u32 big-endian)
 *   context      (remaining bytes, non-empty, ≤255 B)
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
    if (app_name_len == 0u || app_name_len > VAULT_APP_NAME_MAX_LEN || off + app_name_len > lc) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    const uint8_t *app_name = data + off;
    off += app_name_len;

    // Validate appName charset: spec §2.1 requires [a-z0-9\-] only.
    if (!app_name_charset_valid(app_name, app_name_len)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // path_len | path (u32 big-endian per level)
    if (off + 1u > lc) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    uint8_t path_len = data[off++];
    if (path_len == 0u || path_len > VAULT_MAX_PATH_DEPTH || off + (size_t) path_len * 4u > lc) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    uint32_t *const path = G_scratch.derive_ctx.path;
    for (uint8_t i = 0; i < path_len; i++) {
        path[i] = ((uint32_t) data[off] << 24) | ((uint32_t) data[off + 1] << 16) |
                  ((uint32_t) data[off + 2] << 8) | (uint32_t) data[off + 3];
        off += 4u;
    }

    const uint8_t *context = data + off;
    const size_t context_len = lc - off;
    if (context_len == 0u) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // Copy both app_name and context out of the APDU buffer before the blocking
    // display call.  io_ui_process may observe async transport frames; copies into
    // G_scratch.derive_ctx are unconditionally safe.  G_scratch was zeroed above.
    // context_len <= lc <= 255 (single-APDU Lc bound), so context_buf[255] always fits.
    uint8_t *const app_name_buf = G_scratch.derive_ctx.app_name_buf;
    memcpy(app_name_buf, app_name, app_name_len);
    uint8_t *const context_buf = G_scratch.derive_ctx.context_buf;
    memcpy(context_buf, context, context_len);

    // Pre-format the display strings the approval screen will show.
    G_scratch.derive_ctx.path_len = path_len;
    G_scratch.derive_ctx.path_str[0] = 'm';
    G_scratch.derive_ctx.path_str[1] = '/';
    bip32_path_format(path,
                      path_len,
                      G_scratch.derive_ctx.path_str + 2,
                      sizeof(G_scratch.derive_ctx.path_str) - 2);

    // Derive the 33-byte compressed connected public key at the host-supplied path.
    // path[] and connected_pubkey[] live in G_scratch (not on the stack) so that the
    // combined stack depth during the blocking display call stays within budget.
    uint8_t *const connected_pubkey = G_scratch.derive_ctx.connected_pubkey;
    if (crypto_get_compressed_pubkey_at_path(path, path_len, connected_pubkey, NULL) != CX_OK) {
        explicit_bzero(connected_pubkey, VAULT_COMPRESSED_PUBKEY_LEN);
        SEND_SW(dc, SW_BIP32_FAIL);
        return;
    }

    // Spec §2.1: user must approve before the root is derived and returned.
    // NOTE: spec §2.1 also requires "requesting origin" in the dialog; that field
    // has no representation in the current APDU CData layout and cannot be shown
    // without a protocol extension.
    if (!display_derive_context_hash(dc, app_name_buf, app_name_len, context_buf, context_len)) {
        explicit_bzero(connected_pubkey, VAULT_COMPRESSED_PUBKEY_LEN);
        return;  // SW_DENY already sent
    }

    bool ok = hkdf_derive_root(app_name_buf,
                               app_name_len,
                               connected_pubkey,
                               context_buf,
                               context_len,
                               G_vault_context.root);
    explicit_bzero(connected_pubkey, VAULT_COMPRESSED_PUBKEY_LEN);
    // context_buf is no longer needed after derivation; zero it promptly.
    explicit_bzero(G_scratch.derive_ctx.context_buf, sizeof(G_scratch.derive_ctx.context_buf));
    if (!ok) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    if (!vault_context_transition(&G_vault_context, VAULT_STATE_IDLE, VAULT_STATE_HASH_DERIVED)) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    /* F2: persist the BIP-32 path so APPROVE_VAULT_INTENT can verify it matches
     * the depositor derivation path in the intent. */
    memcpy(G_vault_context.derivation_path, path, path_len * sizeof(uint32_t));
    G_vault_context.derivation_path_len = path_len;

    // Return the 32-byte root (the host expands it into the per-vault secrets).
    SEND_RESPONSE(dc, G_vault_context.root, VAULT_HASH256_LEN, SW_OK);
}
