use {
    crate::utils::binary::{BinaryValue, U256},
    bitvec::prelude::*,
};

/**
 * Serializes an X, Y shot into a binary value for the shot circuit
 * 
 * @param x - the horizontal coordinate of the shot
 * @param y - the vertical coordinate of the shot
 * @return - 100-bit integer where the (y*10 + x)th bit is flipped
 */
pub fn serialize(x: u8, y: u8) -> BinaryValue {
    let index = (y * 10 + x) as usize;
    let mut value: U256 = U256::new([0, 0, 0, 0]);
    value.set(index, true);
    BinaryValue::new(value)
}