use {crate::utils::ship::ShipBits, bitvec::prelude::*, halo2_proofs::arithmetic::FieldExt};

/// Converts given bytes to the bits.
pub fn bytes2bits<const B: usize>(num: [u8; 32]) -> [bool; B] {
    let mut bits = [false; B];
    for i in 0..B {
        bits[i] = num[i / 8] & (1 << (i % 8)) != 0;
    }
    bits
}

// https://citizen-stig.github.io/2020/04/04/converting-bits-to-integers-in-rust-using-generics.html
// convert (expected) BitVec of len 100 into u128
pub fn bits2num(bits: &ShipBits) -> u128 {
    bits.iter()
        .fold(0, |result, bit| (result << 1) ^ *bit as u128)
}

pub fn to_field<F: FieldExt, const B: usize>(bits: BitArray<[u64; 4], Lsb0>) -> [F; B] {
    bits.into_inner().view_bits::<Lsb0>()[0..B]
        .into_iter()
        .map(|bit| F::from(*bit))
        .collect::<Vec<F>>()
        .try_into()
        .unwrap()
}
