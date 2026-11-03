Babylon BTC Vault — depositor transaction / PSBT vectors
========================================================

There are two distinct signing paths. The depositor's wallet (device)
signs a different set of transactions in each.

  deposit-flow/          Signed by the device during a normal deposit (plus the
                         refund/abort path). In this flow the VAULT PROVIDER is
                         the claimer — the depositor never signs Claim/Assert.

  depositor-as-claimer/  The live self-claim path. Reached only if the depositor
                         claims independently. This is a protocol capability and
                         is NOT exposed in the current dApp UI. On this path the
                         device signs Claim and Assert (and WronglyChallenged on
                         the dispute path) live, at claim time.


File formats
------------
  hex beginning 70736274ff  = BIP-174 PSBT (device-signing format). Self-contained
        per input: witnessUtxo (amount + scriptPubKey) + tapLeafScript (leaf +
        control block) + tapInternalKey. Everything needed to verify a taproot
        script-path spend is in the PSBT; there is no nonWitnessUtxo.
  hex beginning 02000000    = finalized raw transaction pulled from signet (a FORMAT
        REFERENCE of the broadcast tx, not a PSBT we captured). mempool link below.
  *.json                    = a JSON array of PSBT hexes signed together in ONE
        signPsbts call (signing order = array order). If the wallet exposes no
        batch signPsbts, the SDK falls back to signing them one-by-one via signPsbt.


deposit-flow/  (device-signed during deposit; VP is the claimer)
----------------------------------------------------------------
  pre_pegin.txt         PSBT  ×1   Pre-PegIn.   single signPsbt
  pegin.json            PSBT  ×1   PegIn.       signPsbts (batched if split)
  claimer_payout.json   PSBT  ×5   Per-claimer Payouts (VP + 4 VaultKeepers). The
                                   depositor signs INPUT 0 (vault-UTXO role sig) of
                                   each so any of those claimers can later pay out.
                                   Count = 1 + N_VaultKeepers.  one signPsbts batch
  depositor_graph.json  PSBT  ×9   [0]    depositor's own Payout (input-0 role sig)
                                   [1..8] per-challenger NoPayout (input-0 claimer
                                          presig, one per challenger)
                                   Count = 1 + (N_VaultKeepers + N_UniversalChallengers).
                                   one signPsbts batch
  refund.txt            raw tx     Refund (depositor self-recovery). reference
        https://mempool.space/signet/tx/997fa5a25c48ecc4a64cc55be34b68ad324670dba2d836e672c8496bd10bea89


depositor-as-claimer/  (live self-claim path; NOT in current UI)
----------------------------------------------------------------
  claim.txt             raw tx     Claim. On the live path the device signs ONE
                                   BIP-340 Schnorr over PegIn output 1 — a
                                   SingleKeyConnector P2TR, single leaf
                                   "<depositor> OP_CHECKSIG", script-path. No WOTS,
                                   no multisig, no preimage.
        https://mempool.space/signet/tx/02575e3a44fa04fd4d90a474d1cbc6db3fc601ecbbafe4f32bb295b6bbb78384
  assert.txt            raw tx     Assert (spends Claim output 0). Device signs ONE
                                   Schnorr over the ClaimAssertConnector tapleaf
                                   (sighash Default, script-path). The WOTS reveal in
                                   the witness is SOFTWARE-derived preimage data, NOT
                                   a device signing operation. ~16 KB — the largest
                                   single artifact the device parses (see Size below).
        https://mempool.space/signet/tx/f60aff64e515aef34db8eb1aaf92055d742df2f79c6749f2402c9e60bcda1ec4
  wrongly_challenged.txt raw tx    WronglyChallenged (spends ChallengeAssert output 0;
                                   1-in / 1-out). Device signs ONE Schnorr over the
                                   ChallengeAssert leaf "<Claimer> CHECKSIGVERIFY OP_SIZE
                                   32 EQUALVERIFY OP_SHA256 <hash> OP_EQUAL"; the witness
                                   also reveals a 32-byte hashlock preimage (the GC output
                                   label) — SOFTWARE-derived, NOT a device signing op.
        https://mempool.space/signet/tx/8e0bb385e6445df008dc3f42f68e41e0fb5d7d45685ee87d78c88700c6bc2010


Size & device limits (for buffer planning)
------------------------------------------
The two payout signPsbts batches grow with participant counts — both the NUMBER of
PSBTs and each PSBT's size scale up:
  - claimer_payout: 1 + N_VaultKeepers PSBTs. Each payout's input-0 script embeds
    depositor + VP + every VaultKeeper + every UniversalChallenger (~34 B/key), so
    per-PSBT size is ~linear in (N_VK + N_UC).
  - depositor_graph: 1 + (N_VK + N_UC) PSBTs. NoPayout's signed script is fixed; only
    its control block grows, as ceil(log2(2 + challengers)) (taptree depth).
In shape: depositor_graph grows ~linearly with total challenger count; claimer_payout
grows ~quadratically (1 + N_VK payouts, each ~linear in N_VK + N_UC).

Measured vs modeled payload (binary / hex-on-the-wire):

                         sample (4 VK / 4 UC)     extreme (~30 VK / 30 UC)
  single Payout PSBT     0.70 KB                  ~2.5 KB
  single NoPayout PSBT   0.58 KB                  ~0.66 KB
  claimer_payout batch   3.5 KB / 7 KB            ~78 KB / ~155 KB
  depositor_graph batch  5.3 KB / 11 KB           ~42 KB / ~84 KB

~30 of each is already an extreme deployment; real vaults are smaller. (On-chain
the UniversalChallenger count is hard-capped at 1500 and VaultKeepers have no small
on-chain cap, but those limits are not approached in practice.) At realistic sizes
no signPsbts batch exceeds a few hundred KB. (The extreme column is modeled from the
size laws above; the model reproduces the measured sample column to within ~1%.)

The largest SINGLE PSBT the device parses is the Assert (~16 KB), from the WOTS
reveal in its witness — independent of participant counts. Worth confirming the
device can ingest a PSBT of that size.


Signing notes (verified against btc-vault source)
-------------------------------------------------
- The deposit-flow PSBTs are signed during a normal deposit. Claim, Assert, and
  WronglyChallenged are signed LIVE at claim time (a separate moment). One Schnorr
  per tx; the Assert WOTS reveal and the WronglyChallenged hashlock preimage are
  software-supplied, not device signatures.
- The Payout inputs carry CSV relative timelocks (timelock_pegin on the PegIn
  input, timelock_assert on the Assert input), so the device will see non-zero
  nSequence on those inputs. There is no timelock between Claim and Assert (the
  Assert input uses Sequence::MAX).
