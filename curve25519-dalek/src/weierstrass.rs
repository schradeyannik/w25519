use core::ops::{Add, BitAndAssign};

use field::FieldElement;
use subtle::Choice;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

/// Holds the u-coordinate and v-coordinate of a point on the on the Weierstrass form of Curve25519.
#[derive(Copy, Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WeierstrassPoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
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
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // Non-jacobian short-Weierstrass affine addition (https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html)
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