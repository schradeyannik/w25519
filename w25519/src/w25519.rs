use curve25519_dalek::constants::WEI25519_BASEPOINT;
use curve25519_dalek::weierstrass::{WeierstrassPoint, X25519_BASEPOINT_U, X25519_BASEPOINT_V};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use x25519_dalek::clamp_scalar;

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
        SharedSecret(self.0 * their_public.0)
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
        SharedSecret(&self.0 * their_public.0)
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
        SharedSecret(&self.0 * their_public.0)
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

/// The result of a Diffie-Hellman key exchange.
///
/// Each party computes this using their [`EphemeralSecret`] or [`StaticSecret`] and their
/// counterparty's [`PublicKey`].
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret(pub(crate) WeierstrassPoint);

impl SharedSecret {
    /// Convert this shared secret to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    /// Ensure in constant-time that this shared secret did not result from a
    /// key exchange with non-contributory behaviour.
    ///
    /// In some more exotic protocols which need to guarantee "contributory"
    /// behaviour for both parties, that is, that each party contibuted a public
    /// value which increased the security of the resulting shared secret.
    /// To take an example protocol attack where this could lead to undesireable
    /// results [from Thái "thaidn" Dương](https://vnhacker.blogspot.com/2015/09/why-not-validating-curve25519-public.html):
    ///
    /// > If Mallory replaces Alice's and Bob's public keys with zero, which is
    /// > a valid Curve25519 public key, he would be able to force the ECDH
    /// > shared value to be zero, which is the encoding of the point at infinity,
    /// > and thus get to dictate some publicly known values as the shared
    /// > keys. It still requires an active man-in-the-middle attack to pull the
    /// > trick, after which, however, not only Mallory can decode Alice's data,
    /// > but everyone too! It is also impossible for Alice and Bob to detect the
    /// > intrusion, as they still share the same keys, and can communicate with
    /// > each other as normal.
    ///
    /// The original Curve25519 specification argues that checks for
    /// non-contributory behaviour are "unnecessary for Diffie-Hellman".
    /// Whether this check is necessary for any particular given protocol is
    /// often a matter of debate, which we will not re-hash here, but simply
    /// cite some of the [relevant] [public] [discussions].
    ///
    /// # Returns
    ///
    /// Returns `true` if the key exchange was contributory (good), and `false`
    /// otherwise (can be bad for some protocols).
    ///
    /// [relevant]: https://tools.ietf.org/html/rfc7748#page-15
    /// [public]: https://vnhacker.blogspot.com/2015/09/why-not-validating-curve25519-public.html
    /// [discussions]: https://vnhacker.blogspot.com/2016/08/the-internet-of-broken-protocols.html
    #[must_use]
    pub fn was_contributory(&self) -> bool {
        !self.0.is_identity()
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
    fn w25519_x25519_dh_key_exchange() {
        let mut csprng: OsRng = OsRng;

        let a_secret = StaticSecret::new(csprng);
        let a_pubkey = PublicKey::from(&a_secret);

        let b_secret = StaticSecret::new(csprng);
        let b_pubkey = PublicKey::from(&b_secret);

        let w_shared_a = a_secret.diffie_hellman(&b_pubkey);
        let w_shared_b = b_secret.diffie_hellman(&a_pubkey);

        assert_eq!(shared_a.0, shared_b.0);
    }
}