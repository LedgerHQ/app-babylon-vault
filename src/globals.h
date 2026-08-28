#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "vault_constants.h"
#include "vault_intent.h"
#include "vault_context.h"
#include "vault_script.h"

#include "cx.h"

/** Loaded vault intent. Valid only when G_vault_context.state != VAULT_STATE_IDLE. */
extern vault_intent_t G_vault_intent;

/** Active session context. Always valid; state == VAULT_STATE_IDLE when no session is running. */
extern vault_context_t G_vault_context;

/**
 * @brief In-flight state for a two-phase APPROVE_VAULT_INTENT exchange.
 *
 * Lives from the first P1=0x00 call until all keys are accepted or any
 * error/invalidation occurs.  Zeroed at the start of every P1=0x00 call and
 * inside vault_context_invalidate.
 */
typedef struct {
    /** True after a valid P1=0x00; gates acceptance of P1=0x01 batches. */
    bool scalars_loaded;
    /** Total number of x-only keys stored so far (keepers then challengers). */
    uint8_t keys_received;
} approve_intent_state_t;

/* sizeof(nbgl_layoutTagValue_t) — verified at compile time in display.c */
#define VAULT_DISPLAY_PAIR_SIZE 16

/* Maximum pair count for the scalar-fields segment of the vault intent review.
 * Key pairs are formatted on demand via callback; they are not stored here. */
#define VAULT_SCALAR_PAIRS_MAX 9

/* Scratch layout shared by Screen 2–8 transaction display functions.
 * String sizes verified by static asserts in display.c. */
#define TX_DISPLAY_MAX_PAIRS       6
#define TX_DISPLAY_AMOUNT_STR_SIZE 28 /* MAX_AMOUNT_LENGTH + 1 */
#define TX_DISPLAY_ADDR_STR_SIZE   80 /* MAX_ADDRESS_LENGTH_STR + 1 */
#define TX_DISPLAY_TXID_STR_SIZE   65 /* 32-byte txid as 64 hex chars + NUL */
/* extra_str is the spare value slot: an amount, a chain ID, or a timelock string.
 * Sized for the widest of those — format_timelock_blocks() at the full uint32_t
 * range, "4294967295 blocks (~29826161 days)" (34 chars + NUL). */
#define TX_DISPLAY_EXTRA_STR_SIZE 40

/*
 * Number of independent key-pair slots in display_vault_intent_scratch_t.
 *
 * nbgl_layoutAddTagValueList() stores pair->item and pair->value as raw pointers
 * in text-area objects, then processes all pairs in a loop before rendering.
 * If the callback always returns the same pointer, each successive call overwrites
 * the previous pair's strings.  Using VAULT_KEY_PAIR_SLOTS distinct slots (indexed
 * by pairIndex % VAULT_KEY_PAIR_SLOTS) ensures each live pair has its own buffer.
 * 4 slots safely covers the maximum number of pairs NBGL lays out per page across
 * all supported devices (Nano S+ fits at most 2 key-length pairs per page).
 */
#define VAULT_KEY_PAIR_SLOTS 4

/**
 * Scratch buffers for display_vault_intent.  Lives in G_scratch.display for the
 * duration of the blocking io_ui_process() call.
 *
 * vault_pairs_raw holds the scalar nbgl_layoutTagValue_t array as raw bytes to avoid
 * pulling NBGL headers into globals.h.  display.c asserts sizeof(nbgl_layoutTagValue_t)
 * == VAULT_DISPLAY_PAIR_SIZE and casts the pointer before use.
 *
 * Key pairs (keepers + challengers) are formatted on demand by _vault_key_pair_callback()
 * into key_str[slot] / key_label[slot], returned via key_pair_raw[slot].  The slot is
 * pairIndex % VAULT_KEY_PAIR_SLOTS, giving each concurrently live pair a distinct buffer.
 */
typedef struct {
    uint8_t vault_pairs_raw[VAULT_SCALAR_PAIRS_MAX * VAULT_DISPLAY_PAIR_SIZE];
    char key_str[VAULT_KEY_PAIR_SLOTS][VAULT_HEX_KEY_STR_SIZE];
    char key_label[VAULT_KEY_PAIR_SLOTS][VAULT_KEY_LABEL_SIZE];
    uint8_t key_pair_raw[VAULT_KEY_PAIR_SLOTS][VAULT_DISPLAY_PAIR_SIZE];
} display_vault_intent_scratch_t;

/**
 * Scratch buffers shared by Screen 2–8 transaction display functions.
 * All are mutually exclusive and block on io_ui_process(), so they share
 * one union member.
 *
 * pairs_raw holds the nbgl_layoutTagValue_t array as raw bytes (same pattern as
 * display_vault_intent_scratch_t).  addr_str and txid_str are written by the
 * caller before invoking the display function; NBGL holds pointers to them
 * across io_ui_process.  txid_str is used when a screen needs both a txid and
 * an address (Screen 3), leaving addr_str free for the bech32m address.
 */
typedef struct {
    uint8_t pairs_raw[TX_DISPLAY_MAX_PAIRS * VAULT_DISPLAY_PAIR_SIZE];
    char amount_str[TX_DISPLAY_AMOUNT_STR_SIZE];
    char fee_str[TX_DISPLAY_AMOUNT_STR_SIZE];
    char extra_str[TX_DISPLAY_EXTRA_STR_SIZE];
    char addr_str[TX_DISPLAY_ADDR_STR_SIZE];
    char txid_str[TX_DISPLAY_TXID_STR_SIZE];
} display_tx_scratch_t;

/**
 * Scratch buffer pair for _validate_display_refund leaf-script verification.
 *
 * expected_script aliases script_scratch (union offset 0) — vault_build_htlc_leaf0
 * writes there as usual.  actual_buf starts at union offset VAULT_SCRIPT_MAX_LEN and
 * holds, in sequence: the reconstructed Leaf 1, the PSBT TAP_LEAF_SCRIPT value
 * (leaf0 bytes + version byte, up to _VAULT_MAX_LEAF0_WITH_VERSION bytes), and tap
 * leaf script values read by _tap_leaf_script_callback.  All three require up to
 * VAULT_SCRIPT_MAX_LEN bytes; a compile-time assertion in globals.c verifies this.
 *
 * After the key-display callback refactor, refund_leaf_check_t (5120 B) is the union
 * size dominator, replacing display_vault_intent_scratch_t (now 239 B).
 */
typedef struct {
    uint8_t expected_script[VAULT_SCRIPT_MAX_LEN];
    uint8_t actual_buf[VAULT_SCRIPT_MAX_LEN];
} refund_leaf_check_t;

/**
 * State for the _tap_leaf_script_callback scan over a PSBT input map.
 *
 * Lives in G_scratch.tls — 2636 B saved from BSS versus a static local.
 * The struct is zeroed by _validate_display_refund before each scan.
 */
typedef struct {
    bool found;
    bool ambiguous;
    uint8_t control_block[1 + VAULT_XONLY_PUBKEY_LEN + VAULT_MAX_TAPTREE_DEPTH * VAULT_HASH256_LEN];
    uint16_t control_block_len;
    uint8_t leaf_script[VAULT_SCRIPT_MAX_LEN];
    int leaf_script_len;
    uint8_t leaf_version;

    /* New members MUST go after leaf_script: the sign_standalone aliasing assertions in
     * sign_custom_inputs.c pin offsetof(leaf_script) == 262, and the union overlap
     * assertion in globals.c pins the leaf_script/actual_buf distance.  Note that any
     * field here necessarily aliases leaf_check.actual_buf (leaf_script already overlaps
     * it from union offset 2560), so only transient state belongs in this struct —
     * anything that must survive a leaf_check reconstruction lives in G_leaf_meta. */

    /** Incremental TapLeaf hash state, live only for the duration of one streamed read.
     *  Nothing writes leaf_check.actual_buf while a stream is in flight, so the aliasing
     *  is harmless here. */
    cx_sha256_t leaf_hash_ctx;
} tap_leaf_script_state_t;

/**
 * Durable facts about the leaf script most recently read from a PSBT input.
 *
 * Kept OUTSIDE the G_scratch union: these must stay valid across a
 * leaf_check.expected_script/actual_buf reconstruction, and every byte of
 * tap_leaf_script_state_t past leaf_script aliases leaf_check.actual_buf.  In
 * particular _detect_payout_claimer rebuilds the expected leaf into actual_buf before
 * _refund_verify_taproot_commitment runs, which would otherwise destroy the hash the
 * commitment check depends on.  (Same failure mode, and the same remedy, as the
 * derive-streaming scalars in derive_streaming_state_t.)
 *
 * Zeroed by vault_read_refund_leaf_script / vault_read_payout_leaf_script before each
 * scan, alongside the G_scratch.tls memset.
 *
 * What survives union reuse, and what does not:
 *   - Every member of THIS struct (buffered, last_byte, prefix, hash) stays valid across
 *     a leaf_check reconstruction — that is the whole reason it sits outside the union.
 *   - Nothing in G_scratch.tls does.  leaf_script, leaf_script_len and leaf_version are
 *     members of tap_leaf_script_state_t, which aliases leaf_check.actual_buf; note that
 *     leaf_script_len lands *inside* actual_buf, so rebuilding an expected script there
 *     destroys it.  The layout assertions in sign_custom_inputs.c and globals.c pin the
 *     offsets this depends on.
 * Read leaf_script / leaf_script_len / leaf_version only between a vault_read_* return
 * and the next write to leaf_check.
 */
typedef struct {
    /**
     * True when G_scratch.tls.leaf_script holds the complete script.  False when the
     * script was too large to buffer (real Assert leaves are 11.5-13.6 KB) and was
     * hashed by streaming instead — in that case leaf_script holds nothing usable, and
     * the fields below are the only description of the leaf that outlives a leaf_check
     * reconstruction.  Any consumer that compares the leaf byte-for-byte against a
     * reconstructed script MUST reject when this is false.
     */
    bool buffered;

    /** Final byte of the script (the Assert OP_TRUE terminator check). */
    uint8_t last_byte;

    /** Leading script bytes, zero-padded, for the standalone shape discriminator (which
     *  reads up to VAULT_LEAF_GROUP0_OP_OFF) and the <D> key at [1..32].  Callers must
     *  still check leaf_script_len before trusting a given byte. */
    uint8_t prefix[VAULT_LEAF_PREFIX_LEN];

    /**
     * True when the leaf's leading bytes matched the Assert signer prefix rebuilt from the
     * approved intent — <Depositor> OP_CHECKSIGVERIFY, the keeper N-of-N group and the
     * challenger M-of-M group — and the script continues past it.
     *
     * The prefix reaches ~2.2 KB at 32/32 keys, so it is compared while the leaf streams
     * (see vault_assert_prefix_byte); this flag is the only record of the result once the
     * bytes are gone.  False whenever no intent is loaded, which is what keeps the Assert
     * validator — the one flow with no signing cap, dedup or output enforcement — from
     * accepting a leaf whose challenger set the user never approved.
     */
    bool assert_prefix_ok;

    /** BIP-341 TapLeaf hash over the whole script, however it was read. */
    uint8_t hash[VAULT_HASH256_LEN];
} vault_leaf_meta_t;

/**
 * Streaming-session accumulators for handler_derive_context_hash.
 *
 * Kept OUTSIDE the G_scratch union so that a rejected TAP_LEAF_SCRIPT APDU
 * (or any other handler that writes into the union) cannot leave attacker-
 * controlled bytes where the continuation handler reads them.  Moving these
 * small scalars out eliminates the aliasing OOB-write vector (N-05 / G#1).
 *
 *   streaming_in_progress — gate: true between the P1=0x00 and the final chunk.
 *   p2_mode               — 0x00 = show screen + return root; 0x01 = silent.
 *   app_name_len          — byte length of the app-name received on P1=0x00.
 *   path_len              — number of BIP-32 path components.
 *   context_total_len     — declared context length from the P1=0x00 header.
 *   context_received_len  — bytes accumulated so far; used as memcpy offset.
 *
 * Zeroed by handle_initial_chunk at every P1=0x00 call.
 */
typedef struct {
    bool streaming_in_progress;
    uint8_t p2_mode;
    uint8_t app_name_len;
    uint8_t path_len;
    uint16_t context_total_len;
    uint16_t context_received_len;
} derive_streaming_state_t;

/**
 * Scratch for handler_derive_context_hash (large buffers only).
 *
 * display_tx must be first: display_derive_context_hash writes to display_tx.addr_str
 * for the app-name string while the blocking display call is in progress.
 * All other fields sit above the display_tx footprint and are never clobbered
 * during the call.  After display returns, hkdf_derive_root reads context_buf.
 *
 * Small scalar state (streaming_in_progress, p2_mode, app_name_len, path_len,
 * context_total_len, context_received_len) lives in G_derive_streaming, not here,
 * to prevent union aliasing from other handlers corrupting the streaming session.
 *
 * path[] and connected_pubkey live here (not on the handler stack) so that the
 * combined stack depth during the blocking display call stays within budget.
 *
 * Max context size is VAULT_CONTEXT_MAX_LEN (1024 bytes).
 */
typedef struct {
    display_tx_scratch_t display_tx;
    uint8_t app_name_buf[VAULT_APP_NAME_MAX_LEN];
    uint32_t path[VAULT_MAX_PATH_DEPTH];
    uint8_t connected_pubkey[VAULT_COMPRESSED_PUBKEY_LEN];
    uint8_t context_buf[VAULT_CONTEXT_MAX_LEN];
} derive_context_hash_scratch_t;

/**
 * Scratch for sign_custom_inputs() standalone branch (Refund, Claim, Assert, WC).
 *
 * This struct lives in G_scratch as a union member alongside tap_leaf_script_state_t
 * (tls).  Fields are intentionally ordered so that each write clobbers only tls bytes
 * that are already fully consumed, allowing all locals except input_map to be moved
 * off the stack.  Access ordering (enforced in sign_custom_inputs.c):
 *
 *   leaf_hash  [0..31]:  written by vault_taproot_leaf_hash() after
 *                        vault_read_refund_leaf_script() returns; clobbers
 *                        tls.found (0), tls.ambiguous (1),
 *                        tls.control_block[0..29] (2..31) — all dead.
 *   leaf_key   [32..63]: written after reading tls.leaf_script[0] and [1..32];
 *                        clobbers tls.control_block[30..62] — dead.
 *   input_spk  [64..97]: written by read_p2tr_witness_utxo() only after the
 *                        tls.leaf_script_len check and leaf_key copy are done;
 *                        clobbers tls.control_block[62..95] (64..97) — dead.
 *   deriv_key … sighash: written only after tls is completely consumed.
 *
 * input_map (merkleized_map_commitment_t, 72 B) is passed as output to
 * vault_read_refund_leaf_script(), which also writes G_scratch.tls in the same
 * call; it therefore cannot reside in this struct and stays on the caller's stack.
 *
 * _Static_asserts in sign_custom_inputs.c verify the layout assumptions.
 */
typedef struct {
    uint8_t leaf_hash[VAULT_HASH256_LEN];           /* [0..31]   */
    uint8_t leaf_key[VAULT_XONLY_PUBKEY_LEN];       /* [32..63]  */
    uint8_t input_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN]; /* [64..97]  */
    uint8_t deriv_key[1 + VAULT_XONLY_PUBKEY_LEN];  /* [98..130] */
    /* 1B n_hashes + 2×32B leaf_hashes + 4B fingerprint + path */
    uint8_t
        deriv_val[1 + 2 * VAULT_HASH256_LEN + 4 + VAULT_STANDALONE_PATH_LEN * 4]; /* [131..219] */
    uint32_t sign_path[VAULT_STANDALONE_PATH_LEN];                                /* [220..239] */
    uint8_t xpub_bytes[78]; /* sizeof(serialized_extended_pubkey_t) */            /* [240..317] */
    uint8_t sighash[VAULT_HASH256_LEN];                                           /* [318..349] */
} sign_standalone_scratch_t;

/**
 * Mutually-exclusive scratch union.
 *
 * Each member is live in exactly one handler and is zeroed before use:
 *   - script_scratch    vault_build_* signing hooks
 *   - display           display_vault_intent only (blocks on io_ui_process)
 *   - display_tx        Screen 2–8 transaction display functions
 *   - derive_ctx        handler_derive_context_hash (large buffers only; streaming
 *                       accumulators live in G_derive_streaming outside this union)
 *   - leaf_check        _validate_display_refund leaf-script comparison
 *   - tls               _tap_leaf_script_callback state during refund validation
 *   - sign_standalone   standalone signing branch of sign_custom_inputs()
 *
 * Timing is non-overlapping: tls is populated by the callback inside
 * call_get_merkleized_map_with_callback (step 5), then consumed through
 * step 10; leaf_check.actual_buf is first written at step 11 — safe.
 * display_tx is written (addr_str) and then read (io_ui_process) only after
 * tls and leaf_check are fully consumed.
 *
 * sign_standalone aliases tls byte-by-byte with access-order discipline
 * (see sign_standalone_scratch_t comment above); it does not increase the
 * union size.
 *
 * Size dominator: refund_leaf_check_t at 2 × VAULT_SCRIPT_MAX_LEN = 5120 B.
 * display (display_vault_intent_scratch_t) is now ~524 B — key strings are
 * generated on demand by _vault_key_pair_callback() into VAULT_KEY_PAIR_SLOTS
 * ring-buffer slots rather than pre-formatted for all keys.
 *
 * approve_intent_state_t and derive_streaming_state_t are intentionally NOT in
 * this union.  approve_intent_state_t's boolean guard at byte 0 would be aliased
 * by stale non-zero bytes from other handlers.  derive_streaming_state_t's scalar
 * accumulators (streaming_in_progress, context_received_len, …) are security gates
 * for the multi-chunk streaming path — stale TAP_LEAF_SCRIPT union data must not
 * be able to spoof them or corrupt the write-offset (N-05 / G#1).
 */
typedef union {
    uint8_t script_scratch[VAULT_SCRIPT_MAX_LEN];
    display_vault_intent_scratch_t display;
    display_tx_scratch_t display_tx;
    derive_context_hash_scratch_t derive_ctx;
    refund_leaf_check_t leaf_check;
    tap_leaf_script_state_t tls;
    sign_standalone_scratch_t sign_standalone;
} vault_scratch_t;

extern vault_scratch_t G_scratch;

/**
 * Streaming accumulators for DERIVE_CONTEXT_HASH (INS 0x81).
 *
 * Lives outside G_scratch so union aliasing by other handlers (e.g. the
 * TAP_LEAF_SCRIPT path that writes G_scratch.tls) cannot corrupt the
 * session guards or the context_received_len write offset.
 */
extern derive_streaming_state_t G_derive_streaming;

/**
 * Facts about the leaf script most recently read from a PSBT input.
 *
 * Lives outside G_scratch so a leaf_check reconstruction cannot destroy the TapLeaf hash
 * the taproot commitment check depends on — see vault_leaf_meta_t.
 */
extern vault_leaf_meta_t G_leaf_meta;

/** In-flight state for APPROVE_VAULT_INTENT multi-step exchange. */
extern approve_intent_state_t G_approve_intent_state;
