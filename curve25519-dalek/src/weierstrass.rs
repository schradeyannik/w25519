use core::ops::BitAndAssign;

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