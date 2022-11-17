use bitvec::prelude::*;
use halo2_proofs::arithmetic::FieldExt;

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
pub fn bits2num(bits: &BitVec<u8, Lsb0>) -> u128 {
    bits.iter()
        .fold(0, |result, bit| (result << 1) ^ *bit as u128)
}

/**
 * Convert an array of boolean values (bits) into an array of field elements
 *
 * @param F - the prime field to put the values into
 * @param B - the number of bits / size of the array
 * @param bits - array of
 * @return - fixed size array of field elements derived from binary array
 */
pub fn bits_to_field_elements<F: FieldExt, const B: usize>(bits: [bool; B]) -> [F; B] {
    bits.iter()
        .map(|bit| F::from(*bit))
        .collect::<Vec<F>>()
        .try_into()
        .unwrap()
}

/**
 * Unwrap a BitArray object into an array of booleans of the same size
 * @dev there has to be a better way to do this but I haven't found it yet
 */
pub fn unwrap_bitarr<const S: usize>(bits: BitArray<[u64; 4]>) -> [bool; S] {
    bits.iter()
        .map(|bit| *bit as bool)
        .collect::<Vec<bool>>()
        .try_into()
        .unwrap()
}

/**
 * Unwrap a BitVec object into an array of booleans of the same size
 * @dev there has to be a better way to do this but I haven't found it yet
 */
pub fn unwrap_bitvec<const S: usize>(bits: BitVec<u8>) -> [bool; S] {
    bits.iter()
        .map(|bit| *bit as bool)
        .collect::<Vec<bool>>()
        .try_into()
        .unwrap()
}
