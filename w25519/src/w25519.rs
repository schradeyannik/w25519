use curve25519_dalek::weierstrass::{WeierstrassPoint, X25519_BASEPOINT_U, X25519_BASEPOINT_V};
use curve25519_dalek::scalar::Scalar;
use x25519_dalek::clamp_scalar;

/// The bare, byte-oriented w25519 function, interoperable with RFC7748 by only using the u-coordinates.
/// 
/// This can be used with [`W25519_BASEPOINT_BYTES_U`], [`W25519_BASEPOINT_BYTES_V`] (or [`w25519_base_point`]).
pub fn w25519(k: [u8; 32], u: [u8; 32], v: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    (clamp_scalar(k) * WeierstrassPoint::from_montgomery(u, v)).into_montgomery()
}

pub fn w25519_base_point(k: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    w25519(k, W25519_BASEPOINT_BYTES_U, W25519_BASEPOINT_BYTES_V)
}

pub const W25519_BASEPOINT_BYTES_U: [u8; 32] = X25519_BASEPOINT_U;
pub const W25519_BASEPOINT_BYTES_V: [u8; 32] = X25519_BASEPOINT_V;

#[cfg(test)]
mod test {
    use super::*;

    use rand_core::OsRng;
    use x25519_dalek::x25519;

    #[test]
    fn w25519_matches_x25519() {
        let mut csprng: OsRng = OsRng;

        let k: Scalar = Scalar::random(&mut csprng);
        let (u, _) = w25519(k.to_bytes(), W25519_BASEPOINT_BYTES_U, W25519_BASEPOINT_BYTES_V);
        let expected = x25519(k.to_bytes(), W25519_BASEPOINT_BYTES_U);

        assert_eq!(u, expected);
    }
}