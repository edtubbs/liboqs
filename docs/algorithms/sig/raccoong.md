# Raccoon-G

- **Algorithm type**: Digital signature scheme with HD derivation helpers.
- **Parameter set implemented in liboqs**: `Raccoon-G-44`.
- **Normative source**: *Lattice HD Wallets: Post-Quantum BIP32 Hierarchical Deterministic Wallets from Lattice Assumptions* (ePrint 2026/380), received 2026-02-24, revised 2026-02-27.

## Paper reference summary

This implementation follows the paper's Raccoon-G construction and HD derivation flow:

- **DetKeyGen**: Section 4 (`A <- ExpandA(ρ)`, `s,e <- SampleGaussian`, `t = A·s + e`, `pk=(A,t)`, `sk=s`).
- **RandPK / RandSK**: Section 4 (rerandomization from deterministic `ω`).
- **CKDer_pub / CKDer_priv**: Section 4 (non-hardened derivation from `HMAC-SHA512(chaincode, serialize(pk)||index)`).
- **Gaussian sampling model and bounds**: Section 5.2 and Appendix C.
- **Raccoon-G-44 parameters**: Section 3 and Appendix B.
- **Appendix coverage in the paper**: Appendix A (background), Appendix B (Raccoon-G construction/parameters), Appendix C (omitted proofs). The paper does not provide canonical test vectors.

## Parameter set summary (Raccoon-G-44)

| Parameter set | Security model | Claimed NIST Level | Public key size (bytes) | Secret key size (bytes) | Signature size (bytes) |
|:-------------:|:---------------|-------------------:|------------------------:|------------------------:|-----------------------:|
| Raccoon-G-44  | EUF-CMA        |                  2 |                   16384 |                   32768 |                  32768 |

## HD-specific API surface

`Raccoon-G-44` exposes non-hardened HD helper functions:

- `OQS_SIG_hd_derive_pub`
- `OQS_SIG_hd_derive_priv`
- `OQS_SIG_hd_randpk`
- `OQS_SIG_hd_randsk`

These functions use a 32-byte chaincode and 64-byte rerandomization seed (`ω`, from HMAC-SHA512 output).

## Test-vector policy in this repository

Because ePrint 2026/380 does not include canonical vector dumps, `test_sig_raccoong_vectors` uses deterministic, reproducible in-repo vectors generated from the implemented DetKeyGen/CKDer flows (fixed seed, chaincode, and message).

## Additional implementation reference

The HD derivation wiring was also cross-checked against `p-11/lattice-hd-wallets/src/raccoon` as an implementation reference for derivation flow and serialization usage. Cryptographic behavior in liboqs remains implemented natively in C in this repository.

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
