# Raccoon-G

- **Algorithm type**: Digital signature scheme with HD derivation helpers.
- **Parameter set implemented in liboqs**: `Raccoon-G-44`.
- **Claimed security level**: aligned with ML-DSA-44 (NIST level 2 target).

## Parameter set summary

| Parameter set | Security model | Claimed NIST Level | Public key size (bytes) | Secret key size (bytes) | Signature size (bytes) |
|:-------------:|:---------------|-------------------:|------------------------:|------------------------:|-----------------------:|
| Raccoon-G-44  | EUF-CMA        |                  2 |                   16384 |                   32768 |                  32768 |

## HD-specific API surface

`Raccoon-G-44` exposes non-hardened HD helper functions:

- `OQS_SIG_hd_derive_pub`
- `OQS_SIG_hd_derive_priv`
- `OQS_SIG_hd_randpk`
- `OQS_SIG_hd_randsk`

These functions are provided to support deterministic child key and rerandomization flows with a 32-byte chaincode / rerandomization input.

## How to build and test

```bash
cmake -S . -B build -GNinja
cmake --build build --target oqs test_sig example_sig_raccoong
./build/tests/test_sig Raccoon-G-44 1 1 0
./build/tests/example_sig_raccoong
```

For a focused build that only enables this family:

```bash
cmake -S . -B build-raccoong -GNinja \
  -DOQS_ENABLE_SIG_RACCOON_G=ON \
  -DOQS_ENABLE_SIG_raccoon_g_44=ON
cmake --build build-raccoong --target oqs test_sig
```
