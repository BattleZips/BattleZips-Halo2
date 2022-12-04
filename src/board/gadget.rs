use {
    bitvec::prelude::*,
    crate::utils::{
        board::{ Board, BOARD_SIZE },
        binary::Bits
    },
    halo2_proofs::arithmetic::FieldExt,
    std::marker::PhantomData
};

// private inputs to the witness during proving
pub struct PrivateInput (pub [Bits; 10]); // array of horizontal/ vertical decomposed placement commitments
// public/ instance inputs used by prover, verifier
pub struct PublicInput {
    pub pubkey: [u8; 32], // EdDSA pubkey on Pallas
    pub commitment: Bits // EdDSA signed (by pubkey) poseidon hash of board
}

// Defines all inputs that must be supplied by a client for the proof computation
pub struct WitnessInput {
    private: PrivateInput,
    public: PublicInput
}

/**
 * High level gadget used to drive a PlacementChip
 */
#[derive(Clone, Copy, Debug)]
pub struct BoardGadget<F: FieldExt> {
    pub board: Board,
    _marker: PhantomData<F>
}

impl<F: FieldExt> BoardGadget<F> {

    pub fn new(board: Board) -> Self {
        BoardGadget { board: board, _marker: PhantomData }
    }

    pub fn private_witness(self) -> 
}
