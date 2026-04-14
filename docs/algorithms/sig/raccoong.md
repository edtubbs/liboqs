# Raccoon-G

- **Algorithm type**: Digital signature scheme with HD derivation helpers.
- **Parameter set implemented in liboqs**: `Raccoon-G-44`.
- **Normative source**: *Lattice HD Wallets: Post-Quantum BIP32 Hierarchical Deterministic Wallets from Lattice Assumptions* (ePrint 2026/380), received 2026-02-24, revised 2026-02-27.
- **Historical context**: NIST Round-1 Raccoon submission spec (`raccoon-spec-web.pdf`): <https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-1/spec-files/raccoon-spec-web.pdf>.

## Paper reference summary

This implementation follows the paper's Raccoon-G key-generation and HD derivation flow:

- **DetKeyGen**: Section 4 (`A <- ExpandA(ρ)`, `s,e <- SampleGaussian`, `t = A·s + e`, `pk=(A,t)`, `sk=s`).
- **RandPK / RandSK**: Section 4 (rerandomization from deterministic `ω`).
- **CKDer_pub / CKDer_priv**: Section 4 (non-hardened derivation from `HMAC-SHA512(chaincode, serialize(pk)||index)`).
- **Gaussian sampling model and bounds**: Section 5.2 and Appendix C.
- **Raccoon-G-44 parameters**: Section 3 and Appendix B.
- **Appendix coverage in the paper**: Appendix A (background), Appendix B (Raccoon-G construction/parameters), Appendix C (omitted proofs). The paper does not provide canonical test vectors.

The NIST Round-1 Raccoon document is useful background context, but the current
liboqs `Raccoon-G-44` behavior and vectors in this repository are pinned against
the `p-11/lattice-hd-wallets` reference flow and the ePrint-based HD design
described above.

### Benchmark interpretation note

`Raccoon-G-44` signing is randomized (fresh per-sign nonce seed), so signatures
for the same key/message are expected to differ while still verifying under the
same public key.

Also, when benchmarking via external wrappers, always validate `OQS_STATUS`
returns for each operation. If a harness times only fast error-return paths
(for example, due to invalid input sizes or ignored failures), results can look
implausibly fast.

For sanity-checking, a direct timing run against upstream reference commit
`461a5ed9b6d57e3bf8c381be3bb79325ab21d906` (`p-11/lattice-hd-wallets/src/raccoon/thrc-py`,
`raccoon_primitives`) in this CI-like Linux environment measured approximately:

- `generate_keypair_from_seed`: `~0.226 s`
- `sign_message`: `~0.249 s`
- `verify_signature`: `~0.089 s`

These are only rough environment-dependent reference points, but they help
identify obviously invalid benchmark outputs (for example, sub-microsecond
keygen/sign/verify claims).

## Parameter set summary (Raccoon-G-44)

| Parameter set | Security model | Claimed NIST Level | Public key size (bytes) | Secret key size (bytes) | Signature size (bytes) |
|:-------------:|:---------------|-------------------:|------------------------:|------------------------:|-----------------------:|
| Raccoon-G-44  | EUF-CMA        |                  2 |                   16384 |                   32768 |                  32768 |

For ABI/binary compatibility, these exported sizes are treated as a contract in this repository. Internal tests verify they remain unchanged and that fixed-size key buffers keep canonical zero padding in reserved trailing bytes.

## HD-specific API surface

`Raccoon-G-44` exposes non-hardened HD helper functions:

- `OQS_SIG_hd_derive_pub`
- `OQS_SIG_hd_derive_priv`
- `OQS_SIG_hd_randpk`
- `OQS_SIG_hd_randsk`

These functions use a 32-byte chaincode and 64-byte rerandomization seed (`ω`, from HMAC-SHA512 output).

## Test-vector policy in this repository

Because ePrint 2026/380 does not include canonical vector dumps, `test_sig_raccoong_vectors` pins deterministic known-answer SHA-256 digests that are taken from the reference implementation behavior (`p-11/lattice-hd-wallets/src/raccoon`) for fixed seed/chaincode/message inputs.

For a full vector artifact (not just digests), this repository now includes:

- `tests/KATs/sig/raccoong/reference_kat_p11.json`
- `tests/KATs/sig/raccoong/reference_kat_p11.generation.log`

This file stores complete hex vectors generated from the existing Python/Rust reference implementation flow (commit `461a5ed9b6d57e3bf8c381be3bb79325ab21d906`), including master/child keys and sample signatures for the fixed test inputs.
The accompanying `.generation.log` captures the exact command transcript used to fetch the reference Python files and generate/verify the JSON fixture.

### Reference for Python KAT vectors

Python KAT tests (`tests/test_kat.py` and `tests/test_kat_all.py`) validate the SHA-256 digest of `tests/kat_sig` output. For `Raccoon-G-44`, the `signature || message` KAT composition is implemented in `tests/kat_sig.c` (`combine_message_signature`), and the expected digests are stored in `tests/KATs/sig/kats.json`.

To regenerate and verify these digests:

```bash
cmake -S . -B build -GNinja \
  -DOQS_ENABLE_SIG_RACCOON_G=ON \
  -DOQS_ENABLE_SIG_raccoon_g_44=ON
cmake --build build --target kat_sig
python - <<'PY'
import hashlib, subprocess
for extra, label in [([], "single"), (["--all"], "all")]:
    out = subprocess.check_output(["./build/tests/kat_sig", "Raccoon-G-44", *extra], text=True)
    out = out.replace("\r\n", "\n")
    print(label, hashlib.sha256(out.encode()).hexdigest())
PY
```

## Additional implementation reference

The HD derivation wiring and deterministic KAT flow were cross-checked against `p-11/lattice-hd-wallets/src/raccoon` as an implementation reference for derivation flow and serialization usage. Cryptographic behavior in liboqs remains implemented natively in C in this repository.

## How to build and test

```bash
cmake -S . -B build -GNinja \
  -DOQS_ENABLE_SIG_RACCOON_G=ON \
  -DOQS_ENABLE_SIG_raccoon_g_44=ON
cmake --build build --target oqs test_sig example_sig_raccoong test_sig_raccoong_vectors
./build/tests/test_sig "Raccoon-G-44"
./build/tests/example_sig_raccoong
./build/tests/test_sig_raccoong_vectors
```
