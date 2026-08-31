# Babylon Vault — Proposed base-app change: an abort channel for `call_stream_preimage`

A proposal against **`LedgerHQ/app-bitcoin`** (the `bitcoin_app_base` submodule,
branch `baseapp`), not against this repository. Nothing here can be fixed in
`app-babylon-vault`: the defect is in a base-app helper, and the vault app is one
of several callers.

> **Key takeaway:** `call_stream_preimage` gives its caller **no way to refuse a
> preimage**. The length callback returns `void`, so a caller that dislikes the
> declared length can only stop *processing* the data — it cannot stop the
> *exchange*. A host that declares a ~4 GiB preimage gets ~16.8 million APDU
> round-trips inside a single command, and because the host keeps answering, the
> interruption timeout never fires. Separately, a chunk of `n_bytes == 0` makes
> no progress and loops forever. Impact is **availability only**; recovery is a
> power cycle.

---

## Where this is

| Item | Location |
|---|---|
| Helper | `bitcoin_app_base/src/handler/lib/stream_preimage.c:11` |
| Declaration | `bitcoin_app_base/src/handler/lib/stream_preimage.h:15` |
| Length callback type | `stream_preimage.c:13` — `void (*len_callback)(size_t, void *)` |
| Length callback invoked | `stream_preimage.c:54-56` |
| Chunk loop | `stream_preimage.c:70-110` |
| Buffered counterpart (does it right) | `bitcoin_app_base/src/handler/lib/get_merkle_preimage.c:49` |

---

## The two defects

### 1. The length callback has no return channel

```c
int call_stream_preimage(dispatcher_context_t *dispatcher_context,
                         const uint8_t hash[static 32],
                         void (*len_callback)(size_t, void *),   /* :13 — void */
                         void (*callback)(buffer_t *, void *),
                         void *callback_state);
```

`preimage_len` is a host-declared varint, accepted up to `UINT32_MAX`
(`stream_preimage.c:39-41` rejects only what exceeds it). The callback is
invoked at `:54-56` and its opinion is discarded; the function then computes

```c
size_t bytes_remaining = (size_t) preimage_len - partial_data_len;   /* :70 */
while (bytes_remaining > 0) { ... }                                  /* :72 */
```

and issues one `CCMD_GET_MORE_ELEMENTS` round-trip per chunk of at most 255
bytes. At `UINT32_MAX` that is roughly **16.8 million exchanges** in one
command. Every one is answered by the host, so the dispatcher's interruption
timeout — which fires only when the host goes silent — never triggers. The user
must unplug the device.

The buffered path already handles this correctly. `call_get_merkle_preimage`
compares the declared length against the caller's buffer **before consuming
anything** and returns `-4`:

```c
if (preimage_len - 1 > out_ptr_len) {      /* get_merkle_preimage.c:49 */
    PRINTF("Output buffer too short\n");
    return -4;
}
```

The streaming helper has no equivalent, because a streaming caller has no buffer
to compare against — only a policy, which it currently cannot express.

### 2. A zero-length chunk makes no progress

Inside the loop:

```c
if (elements_len != 1) return -7;        /* :90-93 */
if (n_bytes > bytes_remaining) return -8; /* :95-98 */
...
bytes_remaining -= n_bytes;               /* :109 */
```

`n_bytes == 0` with `elements_len == 1` passes both guards, contributes nothing
to the hash, and leaves `bytes_remaining` unchanged. The loop never terminates,
regardless of the declared length — so even a preimage well inside any cap can
hold the device open indefinitely.

---

## Proposed change

Three edits, all within `stream_preimage.{c,h}`:

1. **Change the length callback to return `bool`** — `true` to proceed, `false`
   to refuse:

   ```c
   int call_stream_preimage(dispatcher_context_t *dispatcher_context,
                            const uint8_t hash[static 32],
                            bool (*len_callback)(size_t, void *),
                            void (*callback)(buffer_t *, void *),
                            void *callback_state);
   ```

2. **Return a negative code when the callback refuses**, before the first chunk
   is requested — mirroring `call_get_merkle_preimage`'s `-4`:

   ```c
   if (len_callback != NULL && !len_callback(preimage_len - 1, callback_state)) {
       return -11;   /* next free code; -10 is the UINT32_MAX rejection */
   }
   ```

3. **Reject `n_bytes == 0`** in the `GET_MORE_ELEMENTS` loop, alongside the
   existing `elements_len` check:

   ```c
   if (n_bytes == 0) {
       PRINTF("Zero-length chunk makes no progress\n");
       return -12;
   }
   ```

With (1) and (2), a caller's cap becomes a real bound on the exchange: the
device answers the first `CCMD_GET_PREIMAGE`, sees the declared length, and ends
the command. With (3), the loop is guaranteed to make progress on every
iteration and therefore to terminate.

### Callers to update

`len_callback` is part of the signature of two wrappers, so the type change
propagates:

| Caller | Passes a length callback? |
|---|---|
| `lib/stream_merkle_leaf_element.c:27` | forwards its own parameter |
| `lib/stream_merkleized_map_value.c:27` | forwards via the above |
| `lib/psbt_parse_rawtx.c:557` | `NULL` — unaffected |
| `sign_psbt/txhashes.c:69` | forwards |
| `sign_psbt/extract_bip32_derivation.c:144` | forwards |
| `app-babylon-vault` `src/sign_psbt_validate.c:251` | `_leaf_stream_len_cb` |

Callers passing `NULL` keep working unchanged. Callers with a real callback gain
the ability to refuse; those that have no length policy return `true`
unconditionally.

---

## Scope

This is a **pre-existing property of the base app** affecting *every*
`call_stream_preimage` caller. It is not introduced by the vault app, and it is
not specific to `PSBT_IN_TAP_LEAF_SCRIPT`. Any caller that streams a
host-declared preimage inherits both defects.

Impact is **availability only** in all cases: the hash check at
`stream_preimage.c:116` still runs, so no unverified data is accepted, no state
is corrupted, and nothing is lost. The device recovers on a power cycle.

## What the vault app does in the meantime

`VAULT_ASSERT_SCRIPT_MAX_LEN` (`src/vault_constants.h`) caps the leaf script the
device will hash by streaming. Because the callback cannot refuse, that cap
bounds the **work**, not the **round-trips**: `_leaf_stream_len_cb`
(`src/sign_psbt_validate.c`) records `len_rejected`, `_leaf_stream_data_cb`
returns immediately for every subsequent chunk without hashing or buffering, and
`_stream_tap_leaf_value` fails the read once the helper returns. The exchange
itself still runs to whatever length the host declared. Once the change above
lands upstream, `_leaf_stream_len_cb` returns `false` in that branch and the
`len_rejected` flag can go away.
