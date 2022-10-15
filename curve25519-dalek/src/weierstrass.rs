use core::ops::{Add, AddAssign, BitAndAssign, Mul, MulAssign};

use field::FieldElement;
use scalar::Scalar;

use subtle::Choice;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

use montgomery::MontgomeryPoint;

// 'a' parameter for Wei25519 in little-endian
// https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23#appendix-E.3
const WEI25519_A: [u8; 32] = [
    0x44, 0xa1, 0x14, 0x49, 0x98, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x2a,
];

/// https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23#appendix-E.2
const DELTA: [u8; 32] = [
    0x51, 0x24, 0xad, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x2a,
];

pub const X25519_BASEPOINT_U: [u8; 32] = crate::constants::X25519_BASEPOINT.0;

/// v-coordinate for the X22159 base point on the Montgomery form of Curve25519
/// https://www.rfc-editor.org/rfc/rfc7748#section-4.1
pub const X25519_BASEPOINT_V: [u8; 32] = [
    0xd9, 0xd3, 0xce, 0x7e, 0xa2, 0xc5, 0xe9, 0x29, 0xb2, 0x61, 0x7c, 0x6d, 0x7e, 0x4d, 0x3d, 0x92, 0x4c, 0xd1, 0x48, 0x77, 0x2c, 0xdd, 0x1e, 0xe0, 0xb4, 0x86, 0xa0, 0xb8, 0xa1, 0x19, 0xae, 0x20,
];

pub const WEI_25519_G_X: [u8; 32] = [
    0x5a, 0x24, 0xad, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x2a,
];
pub const WEI_25519_G_Y: [u8; 32] = X25519_BASEPOINT_V;

/// Holds the u-coordinate and v-coordinate of a point on the Weierstrass form of Curve25519.
/// 
/// Note: all bytes are in Montgomery convention order
#[derive(Copy, Clone, Debug, Hash)]
pub struct WeierstrassPoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl Default for WeierstrassPoint {
    fn default() -> Self {
        WeierstrassPoint {
            x: [0; 32],
            y: [0; 32],
        }
    }
}

fn rev(a: &[u8; 32]) -> [u8; 32] {
    let mut b = [0; 32];
    for i in 0..32 {
        b[31 - i] = a[i];
    }
    b
}

impl PartialEq for WeierstrassPoint {
    fn eq(&self, other: &WeierstrassPoint) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl WeierstrassPoint {
    /// Convert a point (u, v) on the Montgomery form of Curve25519 as `WeierstrassPoint`
    pub fn from_montgomery(u: [u8; 32], v: [u8; 32]) -> WeierstrassPoint {
        // https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23#appendix-D.2
        // (u, v)_M => ((u + A/3)/B, v/B)_W

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

    pub fn double(&self) -> WeierstrassPoint {
        // Non-jacobian short-Weierstrass affine doubling (https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html)
        // x3 = (3*x1^2+a)^2/(2*y1)^2-x1-x1
        // y3 = (2*x1+x1)*(3*x1^2+a)/(2*y1)-(3*x1^2+a)^3/(2*y1)^3-y1
        //
        // Modification:
        // u = (3*x1^2+a)/(2*y1)
        // x3 = u^2-2x1
        // y3 = u*(x1-x3)-y1
        let x1 = FieldElement::from_bytes(&self.x);
        let y1 = FieldElement::from_bytes(&self.y);

        let x1s = x1.square();
        let x1s3 = &(&x1s + &x1s) + &x1s;
        let a = FieldElement::from_bytes(&WEI25519_A);
        let u = &(&x1s3 + &a) * &(&y1 + &y1).invert();
        let x3 = &u.square() - &(&x1 + &x1);
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
                &FieldElement::from_bytes(&a.x),
                &FieldElement::from_bytes(&b.x),
                choice,
            ).to_bytes(),
        }
    }
}

impl Add for WeierstrassPoint {
    type Output = WeierstrassPoint;

    fn add(self, rhs: Self) -> WeierstrassPoint {
        // Non-jacobian short-Weierstrass affine addition (https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html)
        // x3 = (y2-y1)^2/(x2-x1)^2-x1-x2
        // y3 = (2*x1+x2)*(y2-y1)/(x2-x1)-(y2-y1)^3/(x2-x1)^3-y1
        //
        // Modification:
        // u = (y2-y1)/(x2-x1)
        // x3 = u^2-x1-x2
        // y3 = u*(x1-x3)-y1

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

    fn mul(self, scalar: &'b Scalar) -> WeierstrassPoint {
        let mut acc = WeierstrassPoint::default();
        let mut p = *self;

        let bits: [i8; 256] = scalar.bits();

        for i in (0..255).rev() {
            let choice: u8 = (bits[i + 1] ^ bits[i]) as u8;
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
                x: WEI_25519_G_X,
                y: WEI_25519_G_Y,
            }
        )
    }

    #[test]
    fn basepoint_weierstrass_to_montgomery() {
        assert_eq!(
            WeierstrassPoint {
                x: WEI_25519_G_X,
                y: WEI_25519_G_Y,
            }.into_montgomery(),
            (
                X25519_BASEPOINT_U,
                X25519_BASEPOINT_V,
            )
        )
    }

    #[test]
    #[ignore]
    fn eq_defined_mod_p() {
        todo!()
    }

    #[test]
    #[ignore]
    fn scalar_mul_matches_montgomery_ladder() {
        todo!()
    }
}