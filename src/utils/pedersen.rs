use {
    crate::utils::constants::{
        BOARD_COMMITMENT_PERSONALIZATION, BOARD_COMMITMENT_R_BYTES, BOARD_COMMITMENT_V_BYTES,
    },
    halo2_proofs::{
        arithmetic::CurveExt,
        halo2curves::{group::ff::PrimeField, pasta::pallas}
    }
};

/**
 * Compute a pedersen commitment for a given value and trapdoor.
 * 
 * @param message - Base field element of message being committed to
 * @param trapdoor - Scalar field element of the trapdoor to reveal the commitment
 */
pub fn pedersen_commit(message: &pallas::Base, trapdoor: &pallas::Scalar) -> pallas::Point {
    // get curve points used in scalar multiplication
    let hasher = pallas::Point::hash_to_curve(BOARD_COMMITMENT_PERSONALIZATION);
    let v = hasher(&BOARD_COMMITMENT_V_BYTES);
    let r = hasher(&BOARD_COMMITMENT_R_BYTES);
    // convert base field element to scalar
    // https://github.com/zcash/orchard/blob/d05b6cee9df7c4019509e2f54899b5979fb641b5/src/spec.rs#L195
    let message = pallas::Scalar::from_repr(message.to_repr()).unwrap();

    // compute the pedersen commitment for the given value + trapdoor
    v * message + r * trapdoor
}