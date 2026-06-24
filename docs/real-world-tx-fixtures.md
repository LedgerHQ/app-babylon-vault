# Babylon Vault — Real-World Transaction Fixtures

Research into real vault transactions on the Babylon testnet (Bitcoin signet + EVM chain).
Used as cross-validation against our synthetic Python test helpers and C script builders.

## What's in this doc

Vault transactions retrieved from the [Babylon BTCVault Explorer (Xangle)](https://babylon-btcvault-testnet.explorer.xangle.io/home)
and verified on [mempool.space/signet](https://mempool.space/signet/).
Two vault instances were sampled: one from depositor `0xda25fe9c...` (vault `0xd6bd...691a`, Available)
and one from depositor `0xc513fb4b...` (vault `0x6ead...ea986`, Redeemed).

Both run on **Bitcoin signet** (addresses `tb1p…`/`tb1q…`).
The EVM side runs on the Babylon testnet chain.

---

## Status List

| Tx type | Status |
|---|---|
| Pre-PegIn | **found** — 2 real examples |
| PegIn | **found** — 2 real examples, full raw hex available |
| Payout | **missing** — candidate tx `02575e3a…` investigated but found to be a P2WPKH spend unrelated to vault protocol; Payout still needed from Babylon team |
| Refund | **found** — `997fa5a25c48ecc4a64cc55be34b68ad324670dba2d836e672c8496bd10bea89` (unknown vault, depositor `4f98d361…`); HTLC Leaf 1 structure validated ✓ |

Payout fixture must come from the Babylon team — no valid example found on signet as of 2026-06-22.

---

## Transaction Table

| Tx type | Vault | Bitcoin txid | Link | Deciphered contents |
|---|---|---|---|---|
| Pre-PegIn | Vault A (`0xd6bd…`) | `553ecee5883d5fb619c61525762937ac94c5f7a31ff66738a70dbdef29c16aa6` | [mempool](https://mempool.space/signet/tx/553ecee5883d5fb619c61525762937ac94c5f7a31ff66738a70dbdef29c16aa6) | 1 input (user BIP-86 P2TR, 2 931 030 sat); 4 outputs: out0=HTLC P2TR 1 033 668 sat, out1=OP_RETURN 32-byte hashlock, out2=dust 546 sat (user), out3=change 1 896 545 sat (user); version=2, locktime=0 |
| PegIn | Vault A (`0xd6bd…`) | `41bd883be7f787bbbfc24ebd4c33a3e73b7d050f6cc887f66ef64e7024a9e7f7` | [mempool](https://mempool.space/signet/tx/41bd883be7f787bbbfc24ebd4c33a3e73b7d050f6cc887f66ef64e7024a9e7f7) | 1 input = Pre-PegIn out0 (sequence 0xFFFFFFFE); 2 outputs: out0=Vault UTXO P2TR 1 000 000 sat, out1=Depositor Claim P2TR 26 228 sat; fee=7 440 sat; 11-item tapscript witness (HTLC Leaf 0 spend with hashlock preimage + keeper sigs); version=2, locktime=0 |
| Pre-PegIn | Vault B (`0x6ead…`) | `67e6f94340651b38b52994fcc30e34374b5cd93e375b69d0a2865e39341996e2` | [mempool](https://mempool.space/signet/tx/67e6f94340651b38b52994fcc30e34374b5cd93e375b69d0a2865e39341996e2) | Same structure as Vault A Pre-PegIn |
| PegIn | Vault B (`0x6ead…`) | `7aec80c5364bef250d526b04e6878a9995de46359a75292e218cdb8961337581` | [mempool](https://mempool.space/signet/tx/7aec80c5364bef250d526b04e6878a9995de46359a75292e218cdb8961337581) | 1 input = Pre-PegIn out0 (sequence 0xFFFFFFFE, 1 033 668 sat); 2 outputs: out0=Vault UTXO P2TR `51204a204dbb…` 1 000 000 sat, out1=Depositor Claim P2TR `51207f5f92f2…` 26 228 sat; fee=7 440 sat; confirmed block 307 557 |
| Payout | any | — | — | Not yet broadcast on signet; candidate `02575e3a44fa04fd4d90a474d1cbc6db3fc601ecbbafe4f32bb295b6bbb78384` is a P2WPKH-witness tx unrelated to vault tapscript |
| Refund | unknown vault | `997fa5a25c48ecc4a64cc55be34b68ad324670dba2d836e672c8496bd10bea89` | [mempool](https://mempool.space/signet/tx/997fa5a25c48ecc4a64cc55be34b68ad324670dba2d836e672c8496bd10bea89) | 1 input (vault UTXO `71a8f11d…`:0, sequence=432=htlc_refund_timelock); 1 output P2TR 1 455 582 sat; 3-item tapscript witness (depositor 64B schnorr sig + 38B Leaf 1 script + 65B control block); depositor_pk=`4f98d361…`; internal key=VAULT_NUMS_XONLY; timelock 432=`\x02\xb0\x01`; Leaf 1 structure matches `vault_build_htlc_leaf1` ✓ |

---

## Extracted Vault Intent (Vault A)

All fields extracted from the PegIn witness: HTLC Leaf 0 script (315B) + preimage (32B).
Verified: `SHA256(htlc_preimage) == hashlock` embedded in the script. ✓

### Amounts and transaction IDs

| Field | Value |
|---|---|
| `prepegin_txid` (= PegIn input prevout) | `553ecee5883d5fb619c61525762937ac94c5f7a31ff66738a70dbdef29c16aa6` |
| `htlc_vout` | `0` |
| `vault_amount` | `1 000 000 sat` (0.01 BTC) |
| `depositor_claim_value` | `26 228 sat` |
| PegIn fee | `7 440 sat` |

### Cryptographic fields (from HTLC Leaf 0)

| Field | Value |
|---|---|
| `htlc_preimage` | `c0ce5cc7ae33d8ebc7dec1f51e096bddf1e3578828666b54056be63247c38faf` |
| `htlc_hashlock` (= SHA256(preimage)) | `fbf0bacf7b7236ebfd83945626722983d93a51ed77260fbc97cc44684493f780` |
| `depositor_pk` | `165b9e30786a847ae5a51cb8ee0b010ae37e7669fbfe8763866d28da25f2e203` |
| `vault_provider_pk` | `cfccb2f055817506fd17d6041b101348364ce2a4d106f8c62456ec0a565e495d` |
| `keeper_pks[0]` | `9b03efc0a494b29e2ad5631ac15ec32c84c3a5295a64760c3b2ec9c0141c77c7` |
| `keeper_pks[1]` | `cf6828d099112c3ff87d4393e5c222540f6f5cec30be8ea073fc7829dd161ed8` |
| `keeper_pks[2]` | `daae4c4465ea84921a410c3a185bd003cdef9102c7f4760746413922cb478241` |
| `challenger_pks[0]` | `1d40367bb1a1f64e0c7b3abb3a3b8a88fa8f34c24fe255d043b3abaed04adaca` |
| `challenger_pks[1]` | `ed94e11d6a9f04482009e16e30d1b9326f052212f5f0dae6b2c191e15be6e5c4` |
| `challenger_pks[2]` | `f4b542ac5aac10b6ead6bc00a5ffa0d162abbeda4c485ee50d6a77d7e83c9300` |

### Derived output scriptpubkeys (from PegIn outputs)

| Field | Value |
|---|---|
| HTLC scriptpubkey (Pre-PegIn out0) | `5120c64145fc372feecaf3c49c4ff5fb33abc1fc32dda2bdde197af770e76dde1e9a` |
| Vault UTXO scriptpubkey (PegIn out0) | `5120f6a2a7d380def1c142e1baac285989aded617548efca33d0c13bb226a7da8fa7` |
| Depositor Claim scriptpubkey (PegIn out1) | `5120f05be8cf9fd022eb18767c47286ed0edc2017e6264cf85f2904c1cbbfe7f83f4` |

### Pre-PegIn OP_RETURN

Pre-PegIn out1 carries `6a20 5034815498035870d7d1e0dc93a9f95588deac59381792b1d2eaee605f60ad75`
(OP_RETURN OP_PUSHBYTES_32 `5034815498…`). This value is **not** the hashlock — it does
not match `htlc_hashlock` or any SHA256 nesting of it. It is likely a Babylon-protocol
commitment (vault ID, EVM deposit tag, or staker identifier) that the keepers use on the
EVM side. Our firmware validator does not parse OP_RETURN outputs.

### PegIn raw hex

### PegIn raw transaction hex (Vault A)

```
02000000000101a66ac129efbd0da73867f61fa3f7c594ac3729762515c619b65f3d88e5ce3e55
0000000000feffffff0240420f0000000000225120f6a2a7d380def1c142e1baac285989aded6
17548efca33d0c13bb226a7da8fa77466000000000000225120f05be8cf9fd022eb18767c4728
6ed0edc2017e6264cf85f2904c1cbbfe7f83f40b404836f6fa68cb690dad805daf4e6de2112b
ac3475a6c852a27018f0d10d6896e2a24f09ec9f23aeb0fb91f550e40de528dbe4e47c2923bb
8311be7841522ac38340125c1c69592fe35107b2da4ca8de6843b7e86a13413f838a35c57fae
d24b07484e9ba0265fea0d7a13fb1f2271fce0ae4964349f77a3958692ff93e910bb324740d7
8e6c73a9776dde6c426e9ffb1dc92958e1c87c2f44f2b02a90c0242251d5a59410e7ab3b098a
d3863481fdf169898ef0e6abadc957f6a6a1def94d58e7baa94088a1668b7ca4ca78d2d42e24
11029450014d96df726ea082228d1e631d983a721b6cee1a27d20e519f4fd8a0c70afdd4c84c
84e11e3583fc079557e6c66d154340d5425233aacfd13cd0477fbef9c7c15288a74517e94b41
5f822c2017a910fc8b512ef883ef8df4691988ce7de3db52d956536053cdd5999048e7dabca3
6d0d5b40a80eb5cf0f70abbf0ea1c763e15100b9db4caf8fbdadc27f8c26745288ef196c1152
5f9721535c9e22968fe7ef06c25bda16ee1d724b99088b11f8b83216e4f940054d0ba10ae5bf
50309e7a762a89c0fb0d545cef9b35c2d11559c6feb5af9f6abd4b8f288a78716a56f596146f
92973b018662a5f9f3eadcdc2f245a083bb823402d927c372fd8f61ca0ac170ffb737aabb45d
b4255f3369cfbe2dd3c73e63ebddc2d15867ae092e488e54121548dcc264d0eb8a6e8e50133f
9ea23e58d551570520c0ce5cc7ae33d8ebc7dec1f51e096bddf1e3578828666b54056be63247
c38faffd3b0182012088a820fbf0bacf7b7236ebfd83945626722983d93a51ed77260fbc97cc4
4684493f7808820165b9e30786a847ae5a51cb8ee0b010ae37e7669fbfe8763866d28da25f2e2
03ad20cfccb2f055817506fd17d6041b101348364ce2a4d106f8c62456ec0a565e495dad209b0
3efc0a494b29e2ad5631ac15ec32c84c3a5295a64760c3b2ec9c0141c77c7ac20cf6828d09911
2c3ff87d4393e5c222540f6f5cec30be8ea073fc7829dd161ed8ba20daae4c4465ea84921a410
c3a185bd003cdef9102c7f4760746413922cb478241ba539d201d40367bb1a1f64e0c7b3abb3a
3b8a88fa8f34c24fe255d043b3abaed04adacaac20ed94e11d6a9f04482009e16e30d1b9326f0
52212f5f0dae6b2c191e15be6e5c4ba20f4b542ac5aac10b6ead6bc00a5ffa0d162abbeda4c48
5ee50d6a77d7e83c9300ba539c41c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d
547bfee9ace803ac00cef2a5b6f5dedc260c2d94760f1a09cdfd8d26c0d03eb41621f489ae9d8
21700000000
```

The witness (11 items) contains the HTLC Leaf 0 tapscript and its control block.
Control block last item: `c1` (leaf version 0xC0, parity 1) `||` 32-byte internal key
`50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0` (candidate NUMS key)
`||` 32-byte sibling hash (Leaf 1 hash).
The second-to-last witness item is the raw Leaf 0 script (SHA256 hashlock + keeper multisig).

---

## Refund Transaction (unknown vault, depositor `4f98d361…`)

### Overview

txid: `997fa5a25c48ecc4a64cc55be34b68ad324670dba2d836e672c8496bd10bea89`
[mempool.space/signet](https://mempool.space/signet/tx/997fa5a25c48ecc4a64cc55be34b68ad324670dba2d836e672c8496bd10bea89)

- 1 input: `71a8f11d92260031bca22477d39ac639011a7d7d815cc2d94af0e1980f95ba87`:0, **sequence = 0x000001b0 = 432** (enforces htlc_refund_timelock)
- 1 output: 1 455 582 sat to `5120c6328442e0c533af25894c936dd858490e0f1e683ab891ad328a7c256f52bee6` (depositor's P2TR)
- version=2, locktime=0

### Witness (3 items — HTLC Leaf 1 spend)

| Item | Bytes | Content |
|---|---|---|
| `[0]` | 64 | Depositor Schnorr signature (compact, no sighash suffix = default SIGHASH_ALL) |
| `[1]` | 38 | **Leaf 1 tapscript** (see below) |
| `[2]` | 65 | Control block: `0xc1` \|\| internal_key \|\| sibling_hash |

### HTLC Leaf 1 script (38 bytes)

```
20 4f98d361c18784e47496ce973678d69deb2ac75ac327ddeb062a984ac4c6154d  ← PUSH(32) depositor_pk
ad                                                                     ← OP_CHECKSIGVERIFY
02 b001                                                                ← PUSH(2) 432 (LE: 0x01b0)
b2                                                                     ← OP_CSV
```

- `depositor_pk` = `4f98d361c18784e47496ce973678d69deb2ac75ac327ddeb062a984ac4c6154d`
- `htlc_refund_timelock` = 432 = `0x01b0` (2-byte CScriptNum little-endian)
- Script structure matches `vault_build_htlc_leaf1` output exactly ✓

### Control block

- leaf version: `0xC0`, parity: `1`
- internal key: `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0` = **VAULT_NUMS_XONLY** ✓
- sibling hash (Leaf 0): `f2b92eda6f7ee56a1279cb4773d3d3019715bcea74ac4c5f3de3fa3a885fe6d9`

---

## Observations vs Our Implementation

- **Pre-PegIn structure matches**: 1 input (BIP-86 wallet), HTLC at htlc_vout=0, OP_RETURN carries the hashlock — our validator checks `htlc_vout` output, not OP_RETURN.
- **PegIn structure matches**: 1 input sequence=0xFFFFFFFE, 2 P2TR outputs (Vault UTXO + Depositor Claim).
- **Amounts match expected**: vault_amount=1 000 000 sat, depositor_claim_value=26 228 sat.
- **Internal key verified**: PegIn control block internal key `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0` exactly matches `VAULT_NUMS_XONLY` in `src/vault_script.c:92`. This is the standard BIP-341 NUMS point (lift_x of a well-known constant); it is NOT `SHA256("nothing_up_my_sleeve")` — that hash produces a different value. The constant is hardcoded in the C source as a byte literal, not derived at runtime.
- **Refund Leaf 1 structure validated**: `997fa5a2…` spends HTLC Leaf 1 with a 38-byte script matching `vault_build_htlc_leaf1` exactly; VAULT_NUMS_XONLY as internal key confirmed again.
- **Payout test vector must come from Babylon team** — candidate `02575e3a…` is a P2WPKH spend unrelated to the vault; no valid Bitcoin-side Payout found on signet as of 2026-06-22.

---

## Explorer Links

- [Babylon BTCVault Explorer](https://babylon-btcvault-testnet.explorer.xangle.io/home)
- [Vault A detail](https://babylon-btcvault-testnet.explorer.xangle.io/vault/0xd6bddfb6a0d2b104b0ed32da23fc2cd9ca26bb3fe21ba412f805db01eb04691a)
- [Vault B detail](https://babylon-btcvault-testnet.explorer.xangle.io/vault/0x6eadd7fdb4e7558e3f61fc5c05f31141fb7eb099462c7a690c35475e375ea986)
- [mempool.space/signet](https://mempool.space/signet/)
