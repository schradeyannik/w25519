# elusiv-ecc
[![CI](https://github.com/elusiv-privacy/elusiv-ecc/actions/workflows/test.yaml/badge.svg)](https://github.com/elusiv-privacy/elusiv-ecc/actions/workflows/test.yaml)

A pure-Rust constant-time implementation of group operations on Wei25519[^1], the short-Weierstrass representation Curve25519 isomorphism.

These crates extend the functionality of `curve25519-dalek` and `x25519-dalek` with Wei25519 and the crate `w25519` introduces our W25519 ECDH function that is interoperable with X25519.

### W25519
We define W25519 as the X25519 ([RFC7748](https://www.rfc-editor.org/rfc/rfc7748)) function that (internally) uses scalar multiplication over Wei25519 (instead of scalar multiplication over Curve25519).
Hence this function takes a scalar k, a u-coordinate and a v-coordinate (whereas [X25519 takes a scalar k and only a u-coordinate](https://www.rfc-editor.org/rfc/rfc7748#section-5)) and produces a u-coordinate and a v-coordinate as output.

For a Montgomery point (u', v') on Curve25519 the following holds: X25519(k, u') = u(W25519(k, u', v')).

The Diffie-Hellman protocol works the same as it does for [X25519](https://www.rfc-editor.org/rfc/rfc7748#section-6).
The X25519 base point with u:=9 (together with the fixed v-coordinate) is used.
For interoperability with X25519 however, W25519 first needs to be used to generate the public values and both the u-coordinate and v-coordinate need to be exchanged.

### Usage of Wei25519
Wei25519 supports point additions and scalar multiplications with the `WeierstrassPoint` type, as well as functions to switch between Weierstrass and Montgomery representation.

```toml
[dependencies]
curve25519-dalek = { .. , features = ["weierstrass"] }
```

```rust
use curve25519_dalek::weierstrass;
use curve25519_dalek::constants::WEI25519_BASEPOINT;
```

### Usage of W25519
```toml
[dependencies]
w25519 = { .. }
x25519-dalek = { .. } # Only add if you require both W25519 and X25519
```

#### Wrapped DH
The wrapped Diffie-Hellman interfaces are similar to the ones provided by `x25519-dalek`. Both the `x25519-dalek` and `w25519` DH functions return the `x25519-dalek::SharedSecret` type (Montgomery u-coordinate).
To switch from W25519 to X25519, the `w25519::PublicKey` type provides the function `to_x25519_public_key`.

#### Bare minimum DH
The bare minimum W25519 DH can be used as follows for a key exchange between Alice and Bob.

Alice generates random 32-bytes `a_secret`, computes and transmitts `a_u`, `a_v` to Bob.
```rust
let a_secret: [u8; 32] = ..;
let (a_u, a_v) = w25519_base_point(a_secret);
```

Bob generates random 32-bytes `b_secret`, computes and transmitts `b_u`, `b_v` to Alice.
```rust
let b_secret: [u8; 32] = ..;
let (b_u, b_v) = w25519_base_point(b_secret);
```

Alice can now derive the shared secret using `w25519` or `x25519`.
```rust
let (shared_secret, _) = w25519(a_secret, b_u, b_v);
let shared_secret2 = x25519_dalek::x25519(a_secret, b_u);
assert_eq!(shared_secret, shared_secret2);
```

Bob can now also derive the shared secret using `w25519` or `x25519`.
```rust
let (shared_secret, _) = w25519(b_secret, a_u, a_v);
let shared_secret2 = x25519_dalek::x25519(b_secret, a_u);
assert_eq!(shared_secret, shared_secret2);
```

### Dalek Cryptography Crates
Forked versions of Dalek Crypto crates:
- `curve25519-dalek` [release 3.2.1](https://github.com/dalek-cryptography/curve25519-dalek/releases/tag/3.2.1)
- `x25519-dalek` [release 1.2.0](https://github.com/dalek-cryptography/x25519-dalek/releases/tag/1.2.0)

### References
[^1]: Rene Struik (2022) "Alternative Elliptic Curve Representations draft-ietf-lwig-curve-representations-23". URL: [https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23]. Date: 2022.21.01.