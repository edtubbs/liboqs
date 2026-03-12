# Raccoon-G

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**: hardness of Module-LWE with Gaussian noise.
- **Principal submitters**: Ed Tubbs.
- **Authors' website**: https://eprint.iacr.org/2026/380
- **Specification version**: ePrint 2026/380.
- **Primary Source**<a name="primary-source"></a>:
  - **Source**: https://github.com/edtubbs/liboqs/tree/add-raccoon-g/src/sig/raccoong
  - **Implementation license (SPDX-Identifier)**: MIT


## Parameter set summary

|  Parameter set  | Parameter set alias   | Security model   |   Claimed NIST Level |   Public key size (bytes) |   Secret key size (bytes) |   Signature size (bytes) |
|:---------------:|:----------------------|:-----------------|---------------------:|--------------------------:|--------------------------:|-------------------------:|
|  Raccoon-G-44   | NA                    | EUF-CMA          |                    2 |                     16144 |                     32272 |                    20768 |

## Raccoon-G-44 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?‡   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:----------------------|
| [Primary Source](#primary-source) | ref                      | All                         | All                             | None                    | False                              | False                                          | True                  |

Are implementations chosen based on runtime CPU feature detection? **No**.

 ‡For an explanation of what this denotes, consult the [Explanation of Terms](#explanation-of-terms) section at the end of this file.

## Explanation of Terms

- **Large Stack Usage**: Implementations identified as having such may cause failures when running in threads or in constrained environments.