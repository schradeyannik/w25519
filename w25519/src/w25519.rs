use curve25519_dalek::weierstrass::{WeierstrassPoint, X25519_BASEPOINT_U, X25519_BASEPOINT_V};
use curve25519_dalek::scalar::Scalar;
use x25519_dalek::clamp_scalar;

/// The bare, byte-oriented w25519 function, interoperable with RFC7748 by only using the u-coordinates.
/// 
/// This can be used with [`W25519_BASEPOINT_BYTES_U`], [`W25519_BASEPOINT_BYTES_V`].
pub fn w25519(k: [u8; 32], u: [u8; 32], v: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    (clamp_scalar(k) * WeierstrassPoint::from_montgomery(u, v)).into_montgomery()
}

pub const W25519_BASEPOINT_BYTES_U: [u8; 32] = X25519_BASEPOINT_U;
pub const W25519_BASEPOINT_BYTES_V: [u8; 32] = X25519_BASEPOINT_V;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[ignore]
    fn w25519_matches_x25519() {
        todo!()
    }
}