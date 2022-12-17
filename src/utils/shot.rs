use {
    crate::utils::binary::{BinaryValue, U256},
    bitvec::prelude::*,
};

/**
 * Serializes an X, Y shot into a binary value for the shot circuit
 * @param rational actors only use S = 1. Allow S != 1 for unit testing
 * 
 * @param S - number of shots to serialize into one commitment
 * @param x - array of horizontal coordinate of the shots
 * @param y - array of the vertical coordinate of the shots
 * @return - 100-bit integer where the (y*10 + x)th bit is flipped
 */
pub fn serialize<const S: usize>(x: [u8; S], y: [u8; S]) -> BinaryValue {
    let mut value: U256 = U256::new([0, 0, 0, 0]);
    for i in 0..S {
        let index = (y[i] * 10 + x[i]) as usize;
        value.set(index, true);
    }
    BinaryValue::new(value)
}