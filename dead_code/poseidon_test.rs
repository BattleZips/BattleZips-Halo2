// // use crate::utils::{
// //     battleship_ship::{ShipData, ShipType, ShipUtilities},
// //     binary::bits2num,
// // };

use halo2_gadgets::poseidon::{
    primitives::{Hash, ConstantLength, P128Pow5T3, Spec},
};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::pasta::Fp;

#[cfg(test)]
pub mod tests {
    use super::*;
    use halo2_gadgets::poseidon::{
        primitives::{Hash, ConstantLength, P128Pow5T3, Spec},
    };

    #[test]
    fn test_poseidon_hash() {
        let preimage = 8674309u64;
        let hashed = Hash::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from(preimage)]);
        println!("hashed: {:?}", hashed)
    }
}

// // pub struct BoardData {
// //     board: BitVec<u8>,
// //     ships: [Option<ShipData>; 5]
// // }

// // trait BoardUtilities
