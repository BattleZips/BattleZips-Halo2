use {
    bitvec::prelude::*,
    halo2_proofs::{
        arithmetic::FieldExt,
        pasta::{Fp, Fq},
    },
};

/**
 * Binary element with converstion functionality
 * @dev stored in 256 bit integer
 */

pub type U256 = BitArray<[u64; 4], Lsb0>; // 256 bit integer in little endian

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct BinaryValue(U256);

impl BinaryValue {

    // wrap 256 bit BitArray in BinaryValue object
    pub fn new(value: U256) -> BinaryValue {
        BinaryValue(value)
    }

    // unwrap the underlying bitarray
    pub fn into_inner(self) -> U256 {
        self.0
    }

    /**
     * Convert the binary value to an array of bits on a given prime field
     *
     * @param F: the prime field to wrap bits in
     * @param S: the number of bits in the field
     * @return - array of bits of length S on Field F
     */
    pub fn bitfield<F: FieldExt, const S: usize>(self) -> [F; S] {
        self.0.into_inner().view_bits::<Lsb0>()[0..S]
            .into_iter()
            .map(|bit| F::from(*bit))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap()
    }

    /**
     * Return the element as a element on Pallas curve (Fp)
     * @dev hack since can't use FieldExt::from_raw
     *
     * @return - congruent element on Fp
     */
    pub fn fp(self) -> Fp {
        // convert into bytes wide
        Fp::from_raw(self.0.data)
    }

    /**
     * Return the element as a element on Vesta curve (Fq)
     * @dev hack since can't use FieldExt::from_raw
     *
     * @return - congruent element on Fq
     */
    pub fn fq(self) -> Fq {
        // convert into bytes wide
        Fq::from_raw(self.0.data)
    }
}
