//! Scalar multiplication on Wei25519, the Weierstrass form representation of Curve25519

use core::ops::{Add, AddAssign, BitAndAssign, Mul, MulAssign};

use field::FieldElement;
use scalar::Scalar;

use traits::Identity;

use subtle::Choice;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

use montgomery::MontgomeryPoint;

use zeroize::Zeroize;

// 'a' parameter for Wei25519
// https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23#appendix-E.3
const WEI25519_A: [u8; 32] = [
    0x44, 0xa1, 0x14, 0x49, 0x98, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x2a,
];

/// https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23#appendix-E.2
const DELTA: [u8; 32] = [
    0x51, 0x24, 0xad, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x2a,
];

/// u-coordinate for the X22159 base point on the Montgomery form of Curve25519
pub const X25519_BASEPOINT_U: [u8; 32] = crate::constants::X25519_BASEPOINT.0;

/// v-coordinate for the X22159 base point on the Montgomery form of Curve25519
/// https://www.rfc-editor.org/rfc/rfc7748#section-4.1
pub const X25519_BASEPOINT_V: [u8; 32] = [
    0xd9, 0xd3, 0xce, 0x7e, 0xa2, 0xc5, 0xe9, 0x29, 0xb2, 0x61, 0x7c, 0x6d, 0x7e, 0x4d, 0x3d, 0x92, 0x4c, 0xd1, 0x48, 0x77, 0x2c, 0xdd, 0x1e, 0xe0, 0xb4, 0x86, 0xa0, 0xb8, 0xa1, 0x19, 0xae, 0x20,
];

/// x-coordinate for the X22159 base point on Wei25519
pub const WEI25519_G_X: [u8; 32] = [
    0x5a, 0x24, 0xad, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x2a,
];

/// y-coordinate for the X22159 base point on Wei25519
pub const WEI25519_G_Y: [u8; 32] = X25519_BASEPOINT_V;

/// Holds the u-coordinate and v-coordinate of a point on the Weierstrass form of Curve25519.
/// 
/// Note: all bytes are in Montgomery convention order
#[derive(Copy, Clone, Debug, Hash)]
pub struct WeierstrassPoint {
    /// x-coordinate in LE
    pub x: [u8; 32],

    /// y-coordinate in LE
    pub y: [u8; 32],
}

impl From<[u8; 64]> for WeierstrassPoint {
    #[allow(clippy::manual_memcpy)]
    fn from(bytes: [u8; 64]) -> WeierstrassPoint {
        let mut x = [0; 32];
        let mut y = [0; 32];
        for i in 0..32 {
            x[i] = bytes[i];
            y[i] = bytes[i + 32];
        }

        WeierstrassPoint { x, y, }
    }
}

impl Default for WeierstrassPoint {
    fn default() -> Self {
        WeierstrassPoint {
            x: [0; 32],
            y: [0; 32],
        }
    }
}

impl PartialEq for WeierstrassPoint {
    fn eq(&self, other: &WeierstrassPoint) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl Eq for WeierstrassPoint {}

impl Identity for WeierstrassPoint {
    fn identity() -> WeierstrassPoint {
        WeierstrassPoint::default()
    }
}

impl Zeroize for WeierstrassPoint {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
    }
}

impl WeierstrassPoint {
    /// Convert this `WeierstrassPoint` to an array of bytes.
    #[allow(clippy::manual_memcpy)]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0; 64];
        for i in 0..32 {
            b[i] = self.x[i];
            b[i + 32] = self.y[i];
        }
        b
    }

    fn x_ct_eq(&self, other: &Self) -> Choice {
        FieldElement::from_bytes(&self.x)
            .ct_eq(&FieldElement::from_bytes(&other.x))
    }

    fn y_ct_eq(&self, other: &Self) -> Choice {
        FieldElement::from_bytes(&self.y)
            .ct_eq(&FieldElement::from_bytes(&other.y))
    }

    fn at_infinity(&self) -> Choice {
        let i = WeierstrassPoint::default();
        let mut choice = self.x_ct_eq(&i);
        choice.bitand_assign(self.y_ct_eq(&i));
        choice
    }

    /// Convert a point (u, v) on the Montgomery form of Curve25519 as `WeierstrassPoint`
    pub fn from_montgomery(u: [u8; 32], v: [u8; 32]) -> WeierstrassPoint {
        // https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23#appendix-D.2
        // (u, v)_M => ((u + A/3)/B, v/B)_W

        if u == [0; 32] {
            return WeierstrassPoint { x: [0; 32], y: v }
        }

        let u = FieldElement::from_bytes(&u);
        let delta = FieldElement::from_bytes(&DELTA);
        let x = &u + &delta;

        WeierstrassPoint {
            x: x.to_bytes(),
            y: v,
        }
    }

    /// Convert this `WeierstrassPoint` to a point (u, v) on the Montgomery form of Curve25519
    pub fn into_montgomery(&self) -> ([u8; 32], [u8; 32]) {
        // Inverse mapping: https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23#appendix-E.2
        // (x, y)_W = (x - A/3, y)_M

        if self.x == [0; 32] {
            return (self.x, self.y)
        }

        let x = FieldElement::from_bytes(&self.x);
        let delta = FieldElement::from_bytes(&DELTA);
        let u = &x - &delta;

        (u.to_bytes(), self.y)
    }

    /// Convert this `WeierstrassPoint` into a `MontgomeryPoint`
    pub fn into_montgomery_compressed(&self) -> MontgomeryPoint {
        let (u, _) = self.into_montgomery();
        MontgomeryPoint(u)
    }

    /// Constant time (non-jacobian) short-Weierstrass doubling
    pub fn double(&self) -> WeierstrassPoint {
        *self + *self
    }

    /// Adds two short-Weierstrass points in non-constant time
    /// 
    /// # Warning
    /// Do not use this function unless you don't require side-channel-attack resistance.
    pub fn add_not_constant_time(&self, rhs: &WeierstrassPoint) -> WeierstrassPoint {
        // Non-jacobian short-Weierstrass affine addition (https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html)
        // x3 = (y2-y1)^2/(x2-x1)^2-x1-x2
        // y3 = (2*x1+x2)*(y2-y1)/(x2-x1)-(y2-y1)^3/(x2-x1)^3-y1
        //
        // Modification:
        // u = (y2-y1)/(x2-x1)
        // x3 = u^2-x1-x2
        // y3 = u*(x1-x3)-y1

        if self.at_infinity().into() {
            return *rhs
        } else if rhs.at_infinity().into() {
            return *self
        }

        if self.x_ct_eq(rhs).into() {
            if self.y_ct_eq(rhs).into() {
                return self.double()
            } else {
                return WeierstrassPoint::default()
            }
        }

        let x1 = FieldElement::from_bytes(&self.x);
        let y1 = FieldElement::from_bytes(&self.y);

        let x2 = FieldElement::from_bytes(&rhs.x);
        let y2 = FieldElement::from_bytes(&rhs.y);

        let u = &(&y2 - &y1) * &(&x2 - &x1).invert();
        let x3 = &(&u.square() - &x1) - &x2;
        let y3 = &(&u * &(&x1 - &x3)) - &y1;

        WeierstrassPoint {
            x: x3.to_bytes(),
            y: y3.to_bytes(),
        }
    }
}

impl ConstantTimeEq for WeierstrassPoint {
    fn ct_eq(&self, other: &WeierstrassPoint) -> Choice {
        let self_x_fe = FieldElement::from_bytes(&self.x);
        let self_y_fe = FieldElement::from_bytes(&self.y);
        let other_x_fe = FieldElement::from_bytes(&other.x);
        let other_y_fe = FieldElement::from_bytes(&other.y);

        let mut ct_eq = self_x_fe.ct_eq(&other_x_fe);
        ct_eq.bitand_assign(self_y_fe.ct_eq(&other_y_fe));
        ct_eq
    }
}

impl ConditionallySelectable for WeierstrassPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        WeierstrassPoint {
            x: FieldElement::conditional_select(
                &FieldElement::from_bytes(&a.x),
                &FieldElement::from_bytes(&b.x),
                choice,
            ).to_bytes(),
            y: FieldElement::conditional_select(
                &FieldElement::from_bytes(&a.y),
                &FieldElement::from_bytes(&b.y),
                choice,
            ).to_bytes(),
        }
    }
}

impl Add for WeierstrassPoint {
    type Output = WeierstrassPoint;

    /// Constant time (non-jacobian) short-Weierstrass combined affine addition and doubling
    fn add(self, rhs: Self) -> WeierstrassPoint {
        // Formulas for affine addition/doubling: (https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html)
        // Note: Our usage of this function does not require efficiency, instead constant-time execution

        let x1 = FieldElement::from_bytes(&self.x);
        let y1 = FieldElement::from_bytes(&self.y);

        let x2 = FieldElement::from_bytes(&rhs.x);
        let y2 = FieldElement::from_bytes(&rhs.y);

        let x1s = x1.square();
        let x1s3 = &(&x1s + &x1s) + &x1s;
        let a = FieldElement::from_bytes(&WEI25519_A);

        // s = (3*x1^2+a)/(2*y1)
        let s = &(&x1s3 + &a) * &(&y1 + &y1).invert();

        // r = (y2-y1)/(x2-x1)
        let r = &(&y2 - &y1) * &(&x2 - &x1).invert();

        // if x1 = x2 AND y1 = y2: u:=s else: u:=r
        let mut x_eq = self.x_ct_eq(&rhs);
        let y_eq = self.y_ct_eq(&rhs);
        let mut u = r;
        u.conditional_assign(&s, x_eq & y_eq);

        // x3 = u^2-x1-x2
        let mut x3 = &(&u.square() - &x1) - &x2;

        // y3 = u*(x1-x3)-y1
        let mut y3 = &(&u * &(&x1 - &x3)) - &y1;

        // if (x1, y1) = 0: return (x2, y2)
        let at_infinity1 = self.at_infinity();
        x3.conditional_assign(&x2, at_infinity1);
        y3.conditional_assign(&y2, at_infinity1);

        // if (x2, y2) = 0: return (x1, y1)
        let at_infinity2 = rhs.at_infinity() & !at_infinity1;
        x3.conditional_assign(&x1, at_infinity2);
        y3.conditional_assign(&y1, at_infinity2);

        // if x1 = x2 AND y1 != y2: return 0
        x_eq &= !at_infinity1 & !at_infinity2 & !y_eq;
        x3.conditional_assign(&FieldElement::zero(), x_eq);
        y3.conditional_assign(&FieldElement::zero(), x_eq);

        WeierstrassPoint {
            x: x3.to_bytes(),
            y: y3.to_bytes(),
        }
    }
}

impl AddAssign for WeierstrassPoint {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

define_mul_assign_variants!(LHS = WeierstrassPoint, RHS = Scalar);

define_mul_variants!(LHS = WeierstrassPoint, RHS = Scalar, Output = WeierstrassPoint);
define_mul_variants!(LHS = Scalar, RHS = WeierstrassPoint, Output = WeierstrassPoint);

impl<'a, 'b> Mul<&'b Scalar> for &'a WeierstrassPoint {
    type Output = WeierstrassPoint;

    #[allow(clippy::needless_range_loop)]
    fn mul(self, scalar: &'b Scalar) -> WeierstrassPoint {
        let mut acc = WeierstrassPoint::default();
        let mut p = *self;

        let bits: [i8; 256] = scalar.bits();

        for i in 0..255 {
            let choice: u8 = bits[i] as u8;
            let mut a = WeierstrassPoint::default();

            debug_assert!(choice == 0 || choice == 1);

            a.conditional_assign(&p, choice.into());
            acc += a;

            p = p.double();
        }

        acc
    }
}

impl<'b> MulAssign<&'b Scalar> for WeierstrassPoint {
    fn mul_assign(&mut self, scalar: &'b Scalar) {
        *self = *self * scalar;
    }
}

impl<'a, 'b> Mul<&'b WeierstrassPoint> for &'a Scalar {
    type Output = WeierstrassPoint;

    fn mul(self, point: &'b WeierstrassPoint) -> WeierstrassPoint {
        *point * self
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand_core::OsRng;

    #[test]
    fn test_delta() {
        // https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23#appendix-E.2
        // delta:=(p+A)/3

        let three = FieldElement::from_bytes(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        // A_M := 486662 = 0x076d06
        let a = FieldElement::from_bytes(&[
            0x06, 0x6d, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let delta = &(&a * &three.invert());
        assert_eq!(delta.to_bytes(), DELTA);
    }

    #[test]
    fn basepoint_montgomery_to_weierstrass() {
        assert_eq!(
            WeierstrassPoint::from_montgomery(X25519_BASEPOINT_U, X25519_BASEPOINT_V),
            WeierstrassPoint {
                x: WEI25519_G_X,
                y: WEI25519_G_Y,
            }
        )
    }

    #[test]
    fn basepoint_weierstrass_to_montgomery() {
        assert_eq!(
            WeierstrassPoint {
                x: WEI25519_G_X,
                y: WEI25519_G_Y,
            }.into_montgomery(),
            (
                X25519_BASEPOINT_U,
                X25519_BASEPOINT_V,
            )
        )
    }

    #[test]
    fn eq_defined_mod_p() {
        let mut u18_bytes = [0u8; 32]; u18_bytes[0] = 18;

        let u18 = WeierstrassPoint {
            x: u18_bytes,
            y: u18_bytes,
        };
        let u18_unred = WeierstrassPoint {
            x: [255; 32],
            y: [255; 32],
        };

        assert_eq!(u18, u18_unred);
    }

    #[test]
    fn test_map_point_at_infinity() {
        let w = WeierstrassPoint::default();
        assert_eq!(w.into_montgomery_compressed().0, [0; 32]);

        assert_eq!(
            WeierstrassPoint::from_montgomery([0; 32], [0; 32]),
            WeierstrassPoint::default()
        );
    }

    #[test]
    fn scalar_mul_matches_montgomery_scalar_mul() {
        let mut csprng: OsRng = OsRng;

        let s: Scalar = Scalar::random(&mut csprng);
        let p_montgomery: MontgomeryPoint = crate::constants::X25519_BASEPOINT;
        let p_weierstrass: WeierstrassPoint = crate::constants::WEI25519_BASEPOINT;

        let result = s * p_weierstrass;
        let expected = s * p_montgomery;

        assert_eq!(result.into_montgomery_compressed(), expected);
    }
}