use {
    bitvec::prelude::*,
    crate::utils::board::BOARD_SIZE
};

pub struct BitCommitments ([BitArray<[u8; BOARD_SIZE], Lsb0>; 10]);

// private inputs to the witness during proving
pub struct PrivateInput {
    bits: BitCommitments, // array of horizontal/ vertical decomposed placement commitments
    placements: [u128; 10], // integer placement commitments to be decomposed to bits
}

// public/ instance inputs used by prover, verifier
pub struct PublicInput {
    pubkey: [u8; 32], // EdDSA pubkey on Pallas
    commitment: u128 // poseidon 
}

// Defines all inputs that must be supplied by a client for the proof computation
pub struct WitnessInput {
    private: PrivateInput,
    public: PublicInput
}
