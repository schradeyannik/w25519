# elusiv-ecc
[![CI](https://github.com/elusiv-privacy/elusiv-ecc/actions/workflows/test.yaml/badge.svg)](https://github.com/elusiv-privacy/elusiv-ecc/actions/workflows/test.yaml)

This crate extends the functionality of `curve25519-dalek` and `x25519-dalek` with the short-Weierstrass representation Curve25519 isomorphism [Wei25519](https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23).

### Usage of Wei25519
```toml
[dependencies]
curve25519-dalek = { git = "ssh://git@github.com/elusiv-privacy/elusiv-ecc.git", features = ["weierstrass"] }
```

```rust
use curve25519_dalek::weierstrass;
use curve25519_dalek::constants::WEI25519_BASEPOINT;
```

### Dalek Cryptography Crates
- `curve25519-dalek` [release 3.0.0](https://github.com/dalek-cryptography/curve25519-dalek/releases/tag/3.0.0)
- `x25519-dalek` [release 1.2.0](https://github.com/dalek-cryptography/x25519-dalek/releases/tag/1.2.0)