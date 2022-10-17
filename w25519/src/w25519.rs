use curve25519_dalek::constants::WEI25519_BASEPOINT;
use curve25519_dalek::weierstrass::{WeierstrassPoint, X25519_BASEPOINT_U, X25519_BASEPOINT_V};
use curve25519_dalek::scalar::Scalar;
use x25519_dalek::{clamp_scalar, SharedSecret};

use rand_core::CryptoRng;
use rand_core::RngCore;

use zeroize::Zeroize;

/// A Diffie-Hellman public key, corresponding to an [`EphemeralSecret`] or
/// [`StaticSecret`] key.
///
/// We implement `Zeroize` so that downstream consumers may derive it for `Drop`
/// should they wish to erase public keys from memory.  Note that this erasure
/// (in this crate) does *not* automatically happen, but either must be derived
/// for Drop or explicitly called.
#[cfg_attr(feature = "serde", serde(crate = "our_serde"))]
#[cfg_attr(
    feature = "serde",
    derive(our_serde::Serialize, our_serde::Deserialize)
)]
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug, Zeroize)]
pub struct PublicKey(pub(crate) WeierstrassPoint);

impl From<[u8; 64]> for PublicKey {
    /// Given a byte array, construct a w25519 `PublicKey`.
    fn from(bytes: [u8; 64]) -> PublicKey {
        PublicKey(WeierstrassPoint::from(bytes))
    }
}

impl PublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    pub fn to_x25519_public_key(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self.0.into_montgomery_compressed().0)
    }
}

/// A short-lived Diffie-Hellman secret key that can only be used to compute a single
/// [`SharedSecret`].
///
/// This type is identical to the [`StaticSecret`] type, except that the
/// [`EphemeralSecret::diffie_hellman`] method consumes and then wipes the secret key, and there
/// are no serialization methods defined.  This means that [`EphemeralSecret`]s can only be
/// generated from fresh randomness by [`EphemeralSecret::new`] and the compiler statically checks
/// that the resulting secret is used at most once.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct EphemeralSecret(pub(crate) Scalar);

impl EphemeralSecret {
    /// Perform a Diffie-Hellman key agreement between `self` and
    /// `their_public` key to produce a [`SharedSecret`].
    pub fn diffie_hellman(self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret::new((self.0 * their_public.0).into_montgomery_compressed())
    }

    /// Generate an w25519 [`EphemeralSecret`] key.
    pub fn new<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; 32];

        csprng.fill_bytes(&mut bytes);

        EphemeralSecret(clamp_scalar(bytes))
    }
}

impl<'a> From<&'a EphemeralSecret> for PublicKey {
    /// Given an w25519 [`EphemeralSecret`] key, compute its corresponding [`PublicKey`].
    fn from(secret: &'a EphemeralSecret) -> PublicKey {
        PublicKey(&WEI25519_BASEPOINT * &secret.0)
    }
}

/// A Diffie-Hellman secret key which may be used more than once, but is
/// purposefully not serialiseable in order to discourage key-reuse.  This is
/// implemented to facilitate protocols such as Noise (e.g. Noise IK key usage,
/// etc.) and X3DH which require an "ephemeral" key to conduct the
/// Diffie-Hellman operation multiple times throughout the protocol, while the
/// protocol run at a higher level is only conducted once per key.
///
/// Similarly to [`EphemeralSecret`], this type does _not_ have serialisation
/// methods, in order to discourage long-term usage of secret key material. (For
/// long-term secret keys, see [`StaticSecret`].)
///
/// # Warning
///
/// If you're uncertain about whether you should use this, then you likely
/// should not be using this.  Our strongly recommended advice is to use
/// [`EphemeralSecret`] at all times, as that type enforces at compile-time that
/// secret keys are never reused, which can have very serious security
/// implications for many protocols.
#[cfg(feature = "reusable_secrets")]
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ReusableSecret(pub(crate) Scalar);

#[cfg(feature = "reusable_secrets")]
impl ReusableSecret {
    /// Perform a Diffie-Hellman key agreement between `self` and
    /// `their_public` key to produce a [`SharedSecret`].
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret::new((&self.0 * their_public.0).into_montgomery_compressed())
    }

    /// Generate a non-serializeable x25519 [`ReuseableSecret`] key.
    pub fn new<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; 32];

        csprng.fill_bytes(&mut bytes);

        ReusableSecret(clamp_scalar(bytes))
    }
}

#[cfg(feature = "reusable_secrets")]
impl<'a> From<&'a ReusableSecret> for PublicKey {
    /// Given an w25519 [`ReusableSecret`] key, compute its corresponding [`PublicKey`].
    fn from(secret: &'a ReusableSecret) -> PublicKey {
        PublicKey(&WEI25519_BASEPOINT * &secret.0)
    }
}

/// A Diffie-Hellman secret key that can be used to compute multiple [`SharedSecret`]s.
///
/// This type is identical to the [`EphemeralSecret`] type, except that the
/// [`StaticSecret::diffie_hellman`] method does not consume the secret key, and the type provides
/// serialization methods to save and load key material.  This means that the secret may be used
/// multiple times (but does not *have to be*).
///
/// # Warning
///
/// If you're uncertain about whether you should use this, then you likely
/// should not be using this.  Our strongly recommended advice is to use
/// [`EphemeralSecret`] at all times, as that type enforces at compile-time that
/// secret keys are never reused, which can have very serious security
/// implications for many protocols.
#[cfg_attr(feature = "serde", serde(crate = "our_serde"))]
#[cfg_attr(
    feature = "serde",
    derive(our_serde::Serialize, our_serde::Deserialize)
)]
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct StaticSecret(
    #[cfg_attr(feature = "serde", serde(with = "AllowUnreducedScalarBytes"))] pub(crate) Scalar,
);

impl StaticSecret {
    /// Perform a Diffie-Hellman key agreement between `self` and
    /// `their_public` key to produce a `SharedSecret`.
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret::new((&self.0 * their_public.0).into_montgomery_compressed())
    }

    /// Generate an w25519 key.
    pub fn new<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; 32];

        csprng.fill_bytes(&mut bytes);

        StaticSecret(clamp_scalar(bytes))
    }

    /// Extract this key's bytes for serialization.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn to_x25519_static_secret(&self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(self.to_bytes())
    }
}

impl From<[u8; 32]> for StaticSecret {
    /// Load a secret key from a byte array.
    fn from(bytes: [u8; 32]) -> StaticSecret {
        StaticSecret(clamp_scalar(bytes))
    }
}

impl<'a> From<&'a StaticSecret> for PublicKey {
    /// Given an w25519 [`StaticSecret`] key, compute its corresponding [`PublicKey`].
    fn from(secret: &'a StaticSecret) -> PublicKey {
        PublicKey(&WEI25519_BASEPOINT * &secret.0)
    }
}

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

    #[test]
    fn to_x25519_public_key() {
        let csprng: OsRng = OsRng;

        let secret = StaticSecret::new(csprng);
        let pubkey = PublicKey::from(&secret);

        let x25519_pubkey = pubkey.to_x25519_public_key();

        assert_eq!(
            pubkey.0.into_montgomery_compressed().0,
            x25519_pubkey.to_bytes()
        );
    }

    #[test]
    fn w25519_x25519_dh_key_exchange() {
        let csprng: OsRng = OsRng;

        let a_secret_w = StaticSecret::new(csprng);
        let a_pubkey_w = PublicKey::from(&a_secret_w);

        let b_secret_w = StaticSecret::new(csprng);
        let b_pubkey_w = PublicKey::from(&b_secret_w);

        let a_shared_w = a_secret_w.diffie_hellman(&b_pubkey_w);
        let b_shared_w = b_secret_w.diffie_hellman(&a_pubkey_w);

        assert_eq!(a_shared_w.to_bytes(), b_shared_w.to_bytes());

        let a_secret_x = a_secret_w.to_x25519_static_secret();
        let a_pubkey_x = x25519_dalek::PublicKey::from(&a_secret_x);

        let b_secret_x = b_secret_w.to_x25519_static_secret();
        let b_pubkey_x = x25519_dalek::PublicKey::from(&b_secret_x);

        let a_shared_x = a_secret_x.diffie_hellman(&b_pubkey_x);
        let b_shared_x = b_secret_x.diffie_hellman(&a_pubkey_x);

        assert_eq!(a_shared_x.to_bytes(), a_shared_w.to_bytes());
        assert_eq!(a_shared_x.to_bytes(), b_shared_x.to_bytes());
    }
}