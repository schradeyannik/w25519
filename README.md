# elusiv-ecc
[![CI](https://github.com/elusiv-privacy/elusiv-ecc/actions/workflows/test.yaml/badge.svg)](https://github.com/elusiv-privacy/elusiv-ecc/actions/workflows/test.yaml)

This crate extends the functionality of `curve25519-dalek` and `x25519-dalek` with the short-Weierstrass representation Curve25519 isomorphism [Wei25519](https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23).

### Usage of Wei25519
Import `curve25519-dalek` from this workspace either with the `default` or `weierstrass` feature.

### Dalek Cryptography Crates
- `curve25519-dalek` [release 3.0.0](https://github.com/dalek-cryptography/curve25519-dalek/releases/tag/3.0.0)
- `x25519-dalek` [release 1.2.0](https://github.com/dalek-cryptography/x25519-dalek/releases/tag/1.2.0)