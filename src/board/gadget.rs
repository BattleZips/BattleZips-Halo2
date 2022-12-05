use {
    crate::{
        placement::gadget::PlacementBits,
        utils::{
            binary::BinaryValue,
            board::{Board, BOARD_SIZE},
        },
    },
    halo2_proofs::{arithmetic::FieldExt, circuit::AssignedCell},
    std::marker::PhantomData,
};

pub type Commitments<F: FieldExt> = [AssignedCell<F, F>; 10];
pub type Placements<F: FieldExt> = [PlacementBits<F>; 10];

// private inputs to the witness during proving
pub struct PrivateInput(pub [BinaryValue; 10]); // array of horizontal/ vertical decomposed placement commitments
                                                // public/ instance inputs used by prover, verifier
pub struct PublicInput {
    pub pubkey: [BinaryValue; 2], // EdDSA pubkey on Pallas
    pub commitment: BinaryValue,  // EdDSA signed (by pubkey) poseidon hash of board
}

// Defines all inputs that must be supplied by a client for the proof computation
pub struct WitnessInput {
    private: PrivateInput,
    public: PublicInput,
}

/**
 * High level gadget used to drive a PlacementChip
 */
#[derive(Clone, Copy, Debug)]
pub struct BoardGadget<F: FieldExt> {
    pub board: Board,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BoardGadget<F> {
    pub fn new(board: Board) -> Self {
        BoardGadget {
            board: board,
            _marker: PhantomData,
        }
    }

    /**
     * Export private witness inputs
     * @dev due to Fp::from_raw() not being on FieldExt, export on Pallas
     *
     * @return - array of 10 ship commitments: [H5, V5, H4, V4, H3a, V3a, H3b, V3b, H2, V2]
     */
    pub fn private_witness(self) -> [F; 10] {
        let binary = self.board.private_witness().0;
        let mut witness = Vec::<F>::new();
        for commitment in binary {
            witness.push(F::from_u128(commitment.lower_u128()));
        }
        witness.try_into().unwrap()
    }

    /**
     * Return the little-endian binary decomposition for all placements
     *
     * @return - array of 10 PlacementBits objects
     */
    pub fn decompose_bits(self) -> [[F; BOARD_SIZE]; 10] {
        self.board
            .private_witness()
            .0
            .iter()
            .map(|commitment| commitment.bitfield::<F, BOARD_SIZE>())
            .collect::<Vec<[F; BOARD_SIZE]>>()
            .try_into()
            .unwrap()
    }

    /**
     * Return a label for commitments in debugging
     *
     * @param i - the enumerable index [0-9] of commitment types
     * @return - the label to be used in debugging messages
     */
    pub fn commitment_label(i: usize) -> String {
        String::from(match i {
            0 => "H5",
            1 => "V5",
            2 => "H4",
            3 => "V4",
            4 => "H3a",
            5 => "V3a",
            6 => "H3b",
            7 => "V3b",
            8 => "H2",
            9 => "V2",
            _other => "NULL"
        })
    }
}
