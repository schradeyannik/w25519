use core::ops::{Add, AddAssign, BitAndAssign, Mul, MulAssign};

use field::FieldElement;
use scalar::Scalar;

use subtle::Choice;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

use montgomery::MontgomeryPoint;

/// 'a' parameter for Wei25519
/// https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23#appendix-E.3
/// 19298681539552699237261830834781317975544997444273427339909597334573241639236
const WEI25519_A: [u8; 32] = [
    0x2A, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x98, 0x49, 0x14, 0xA1, 0x44,
];

const THREE: [u8; 32] = [
    3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Holds the u-coordinate and v-coordinate of a point on the Weierstrass form of Curve25519.
/// 
/// Note: all bytes are in Montgomery convention order
#[derive(Copy, Clone, Debug, Hash)]
pub struct WeierstrassPoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl WeierstrassPoint {
    pub fn zero() -> WeierstrassPoint {
        WeierstrassPoint {
            x: [0; 32],
            y: [0; 32],
        }
    }

    /// Convert a point (u, v) on the Montgomery form of Curve25519 as `WeierstrassPoint`
    pub fn from_montgomery(u: [u8; 32], v: [u8; 32]) -> WeierstrassPoint {
        // https://datatracker.ietf.org/doc/html/draft-ietf-lwig-curve-representations-23#appendix-D.2
        // (u, v)_M => ((u + A/3)/B, v/B)_W

        let u = FieldElement::from_bytes(&u);
        let three = FieldElement::from_bytes(&THREE);
        let a = FieldElement::from_bytes(&WEI25519_A);
        let x = &u + &(&a * &three.invert());

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
        let three = FieldElement::from_bytes(&THREE);
        let a = FieldElement::from_bytes(&WEI25519_A);
        let u = &x - &(&a * &three.invert());

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

        let three = FieldElement::from_bytes(&THREE);
        let a = FieldElement::from_bytes(&WEI25519_A);
        let u = &(&(&three * &x1.square()) + &a) * &(&y1 + &y1).invert();
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
        let mut acc = WeierstrassPoint::zero();
        let mut p = *self;

        let bits: [i8; 256] = scalar.bits();

        for i in (0..255).rev() {
            let choice: u8 = (bits[i + 1] ^ bits[i]) as u8;
            let mut a = WeierstrassPoint::zero();

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
    #[test]
    fn basepoint_montgomery_to_weierstrass() {
        todo!()
    }

    #[test]
    fn basepoint_weierstrass_to_edwards() {
        todo!()
    }

    #[test]
    fn eq_defined_mod_p() {
        todo!()
    }

    #[test]
    fn scalar_mul_matches_montgomery_ladder() {
        todo!()
    }
}