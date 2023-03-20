use {
    crate::{
        chips::board::{BoardChip, BoardConfig},
        utils::binary::BinaryValue,
    },
    halo2_proofs::{
        halo2curves::{
            group::Curve,
            pasta::pallas
        },
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },

};

#[derive(Debug, Clone)]
pub struct BoardCircuit {
    pub ship_commitments: [BinaryValue; 10],
    pub board: BinaryValue,
    pub board_commitment_trapdoor: pallas::Scalar,
}

impl Circuit<pallas::Base> for BoardCircuit {
    type Config = BoardConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        // @TODO fix
        BoardCircuit::new(
            self.ship_commitments,
            self.board,
            self.board_commitment_trapdoor,
        )
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        BoardChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let chip = BoardChip::new(config);
        chip.synthesize(
            layouter,
            self.ship_commitments,
            self.board,
            self.board_commitment_trapdoor,
        )
    }
}

impl BoardCircuit {
    /**
     * Construct a new board circuit given a commitment to ship placements
     * @dev handles all trace/ gadget construction given deck input
     *
     * @param ship_commitments - assignments for each of the ships according to order in chips::board::commitment_label
     * @param board - the resulting board state when all ship commitments are transposed onto one bitfield
     * @param board_commitment_trapdoor - randomly sampled blinding factor for board commitment
     * @return - instantiated BoardCircuit object containing BoardGadget
     */
    pub fn new(
        ship_commitments: [BinaryValue; 10],
        board: BinaryValue,
        board_commitment_trapdoor: pallas::Scalar,
    ) -> BoardCircuit {
        BoardCircuit {
            ship_commitments,
            board,
            board_commitment_trapdoor,
        }
    }
}

#[cfg(test)]
mod test {

    use {
        super::*,
        crate::utils::{
            board::Board,
            deck::Deck,
            pedersen::pedersen_commit,
            ship::{WitnessOption, DEFAULT_WITNESS_OPTIONS},
        },
        halo2_proofs::{
            arithmetic::{CurveAffine, Field},
            dev::{FailureLocation, MockProver, VerifyFailure},
            halo2curves::{
                group::Curve,
                pasta::{pallas, vesta},
            },
            plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Any, SingleVerifier},
            poly::commitment::Params,
            transcript::{Blake2bRead, Blake2bWrite, Challenge255},
        },
        rand::rngs::OsRng,
    };

    #[test]
    fn valid_0() {
        // construct battleship board pattern #1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = board.state(DEFAULT_WITNESS_OPTIONS).to_fp();
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
            trapdoor,
        );
        // prove board pattern 1 is a valid configuration, and constrain the output of the board commitment
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect success
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn valid_1() {
        // construct battleship board pattern #2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
            trapdoor,
        );
        // prove board pattern 2 is a valid configuration, and constrain the output of the board commitment
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect success
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn invalid_placement_none() {
        // construct battleship board pattern #1 with Carrier missing
        let board = Board::from(&Deck::from([
            None,
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, true)),
        ]));
        // modify the shot_commitment for H5, V5 by setting both equal to 0
        let mut shot_commitments = board.witness(DEFAULT_WITNESS_OPTIONS);
        shot_commitments[1] = BinaryValue::from_u8(0);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
            trapdoor,
        );
        // prove that attempting to not assign a ship fails verification
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                // expect 5 bits, counts 0 bits
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (15, "running sum constraints").into(),
                        0,
                        "Placed ship of correct length",
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (13, "constrain running sum output").into(),
                        offset: 0,
                    },
                    cell_values: vec![(((Any::Advice, 1).into(), 0).into(), String::from("0"),),]
                },
                // expects one full (true, true, true, true, true) 5-bit window, counts none
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (15, "running sum constraints").into(),
                        1,
                        "One full bit window",
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (13, "constrain running sum output").into(),
                        offset: 0,
                    },
                    cell_values: vec![(((Any::Advice, 2).into(), 0).into(), String::from("0"),),]
                }
            ])
        );
    }

    #[test]
    fn invalid_placement_dual() {
        // construct battleship board pattern #1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // modify the shot_commitment for H5, V5 by setting horizontal as expected and vertical = 1 (not allowed)
        let witness_options = [
            WitnessOption::DualPlacement,
            WitnessOption::Default,
            WitnessOption::Default,
            WitnessOption::Default,
            WitnessOption::Default,
        ];
        let ship_commitments = board.witness(witness_options);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(witness_options).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(ship_commitments, board.state(witness_options), trapdoor);
        // prove that attempting to assign both horizontal and vertical placements to a single ship fails verification
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (56, "Commitment orientation H OR V == 0 constraint").into(),
                    0,
                    "Aircraft Carrier H OR V == 0",
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (0, "load ship placements").into(),
                    offset: 0,
                },
                cell_values: vec![
                    (
                        ((Any::Advice, 0).into(), 0).into(),
                        String::from("0x200000000"),
                    ),
                    (
                        ((Any::Advice, 1).into(), 0).into(),
                        String::from("0x3c00000000"),
                    )
                ]
            },])
        );
    }

    #[test]
    fn invalid_placement_nonconsecutive() {
        // construct battleship board pattern #1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // modify the shot_commitment for H5, V5 by setting horizontal as expected and vertical = 1 (not allowed)
        let witness_options = [
            WitnessOption::Nonconsecutive,
            WitnessOption::Default,
            WitnessOption::Default,
            WitnessOption::Default,
            WitnessOption::Default,
        ];
        let ship_commitments = board.witness(witness_options);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(witness_options).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(ship_commitments, board.state(witness_options), trapdoor);
        // prove that not having a full consecutive ship placement fails verification
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (15, "running sum constraints").into(),
                    1,
                    "One full bit window",
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (13, "constrain running sum output").into(),
                    offset: 0,
                },
                cell_values: vec![(((Any::Advice, 2).into(), 0).into(), String::from("0"),),]
            }])
        );
    }

    #[test]
    fn invalid_placement_extra_bit() {
        // construct battleship board pattern #1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // modify the shot_commitment for H5, V5 by setting horizontal as expected and vertical = 1 (not allowed)
        let witness_options = [
            WitnessOption::ExtraBit,
            WitnessOption::Default,
            WitnessOption::Default,
            WitnessOption::Default,
            WitnessOption::Default,
        ];
        let ship_commitments = board.witness(witness_options);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(witness_options).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(ship_commitments, board.state(witness_options), trapdoor);
        // prove that including extra bits in a ship placement fails verification
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (15, "running sum constraints").into(),
                    0,
                    "Placed ship of correct length",
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (13, "constrain running sum output").into(),
                    offset: 0,
                },
                cell_values: vec![(((Any::Advice, 1).into(), 0).into(), String::from("0x6"),),]
            }])
        );
    }

    #[test]
    fn invalid_placement_oversized() {
        // construct battleship board pattern #1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // modify the shot_commitment for H4 by adding an extra bit making ship length 5 when it should be 4
        let witness_options = [
            WitnessOption::Default,
            WitnessOption::Oversized,
            WitnessOption::Default,
            WitnessOption::Default,
            WitnessOption::Default,
        ];
        let ship_commitments = board.witness(witness_options);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(witness_options).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(ship_commitments, board.state(witness_options), trapdoor);
        // prove that placing an oversized ship fails verification
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                // counted 5 bits for battleship placement chip expecting 4 bits
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (20, "running sum constraints").into(),
                        0,
                        "Placed ship of correct length",
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (16, "constrain running sum output").into(),
                        offset: 0,
                    },
                    cell_values: vec![(((Any::Advice, 1).into(), 0).into(), String::from("0x5"),),]
                },
                // counted 2 full bit windows for battleship placement chip expecting 1 full bit window
                // full window at 54, 64, 74, 84 expected, full window at 64, 74, 84, 94 not expected
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (20, "running sum constraints").into(),
                        1,
                        "One full bit window",
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (16, "constrain running sum output").into(),
                        offset: 0,
                    },
                    cell_values: vec![(((Any::Advice, 2).into(), 0).into(), String::from("0x2"),),]
                }
            ])
        );
    }

    #[test]
    fn invalid_placement_undersized() {
        // construct battleship board pattern #2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // modify the shot_commitment for V5 by removing last bit making ship length 1 when it should be 2
        let witness_options = [
            WitnessOption::Default,
            WitnessOption::Default,
            WitnessOption::Default,
            WitnessOption::Default,
            WitnessOption::Undersized,
        ];
        let ship_commitments = board.witness(witness_options);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(witness_options).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(ship_commitments, board.state(witness_options), trapdoor);
        // prove that placing an undersized ship fails verification
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                // counted 1 bits for destroyer placement, expecting 2
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (35, "running sum constraints").into(),
                        0,
                        "Placed ship of correct length",
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (25, "constrain running sum output").into(),
                        offset: 0,
                    },
                    cell_values: vec![(((Any::Advice, 1).into(), 0).into(), String::from("1"),),]
                },
                // counted 0 full bit windows, expecting 1
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (35, "running sum constraints").into(),
                        1,
                        "One full bit window",
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (25, "constrain running sum output").into(),
                        offset: 0,
                    },
                    cell_values: vec![(((Any::Advice, 2).into(), 0).into(), String::from("0"),),]
                }
            ])
        );
    }

    #[test]
    fn invalid_horizontal_row_overflow() {
        // construct battleship board pattern #2 with modification
        // set cruiser ship to be placed at (9, 0) which is out of bounds by 2 bits
        // 9 valid, wraps around to 10, 11
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((9, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
            trapdoor,
        );
        // prove that attempting to place ships that overflow 10 units horizontally fails verification
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (25, "running sum constraints").into(),
                    1,
                    "One full bit window",
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (19, "constrain running sum output").into(),
                    offset: 0,
                },
                cell_values: vec![(((Any::Advice, 2).into(), 0).into(), String::from("0"),),]
            }])
        );
    }

    #[test]
    fn invalid_vertical_row_overflow() {
        // construct battleship board pattern #1 with modification
        // set carrier ship to be placed vertically at (3, 6) which is out of bounds by 1 bit
        // 63, 73, 83, 93 valid; wraps around to 4
        let board = Board::from(&Deck::from([
            Some((3, 6, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
            trapdoor,
        );
        // prove that attempting to place ships that overflow 10 units vertically fails verification
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (15, "running sum constraints").into(),
                    1,
                    "One full bit window",
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (13, "constrain running sum output").into(),
                    offset: 0,
                },
                cell_values: vec![(((Any::Advice, 2).into(), 0).into(), String::from("0"),),]
            }])
        );
    }

    #[test]
    fn invalid_collision_no_transpose() {
        // @notice: no transpose means there is a horizontal collision found without any transposition
        // construct battleship board pattern #1 with modification
        // set crusier ship to be placed horizontally at (4, 1) which collides with destroyer ship at (6, 1)
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((4, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
            trapdoor,
        );
        // prove that attempting to place ships that collide horizontally fails verification
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                // sum of all bits in commitment row != transposed commitment bit
                //      this is constrained to be binary, so it is impossible to not be 0 or 1
                //      or else bits2num throws constraint error instead
                //      fails when expects sum = 2 but gets sum = 1
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (36, "transpose row constraint").into(),
                        0,
                        "Constrain trace value integrity",
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (26, "Transpose ship commitments").into(),
                        offset: 16,
                    },
                    cell_values: vec![
                        (((Any::Advice, 0).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 1).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 2).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 3).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 4).into(), 0).into(), String::from("1"),),
                        (((Any::Advice, 5).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 6).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 7).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 8).into(), 0).into(), String::from("1"),),
                        (((Any::Advice, 9).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 10).into(), 0).into(), String::from("1"),)
                    ]
                },
                // fail constraint: sum of all bits in commitment row != 0 or 1
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (36, "transpose row constraint").into(),
                        1,
                        "Constrain transposition of bit",
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (26, "Transpose ship commitments").into(),
                        offset: 16,
                    },
                    cell_values: vec![
                        (((Any::Advice, 0).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 1).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 2).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 3).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 4).into(), 0).into(), String::from("1"),),
                        (((Any::Advice, 5).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 6).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 7).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 8).into(), 0).into(), String::from("1"),),
                        (((Any::Advice, 9).into(), 0).into(), String::from("0"),),
                    ]
                }
            ])
        );
    }

    #[test]
    fn invalid_collision_transposed() {
        // @notice: transposed means the placement commitment would be valid if
        //          vertical but collides when transposed as horizontal
        // construct battleship board pattern #2 with modification
        // set destroyer ship to be placed vertically at (6, 3) which collides with battleship ship at (6, 4)
        //          if destroyer placed horizontally, would produce a valid board configuration
        // construct battleship board pattern #2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 3, true)),
        ]));
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
            trapdoor,
        );
        // prove that attempting to place ships that collide vertically fails verification
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                // sum of all bits in commitment row != transposed commitment bit
                //      this is constrained to be binary, so it is impossible to not be 0 or 1
                //      or else bits2num throws constraint error instead
                //      fails when expects sum = 2 but gets sum = 1
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (36, "transpose row constraint").into(),
                        0,
                        "Constrain trace value integrity",
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (26, "Transpose ship commitments").into(),
                        offset: 46,
                    },
                    cell_values: vec![
                        (((Any::Advice, 0).into(), 0).into(), String::from("1"),),
                        (((Any::Advice, 1).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 2).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 3).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 4).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 5).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 6).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 7).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 8).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 9).into(), 0).into(), String::from("1"),),
                        (((Any::Advice, 10).into(), 0).into(), String::from("1"),)
                    ]
                },
                // fail constraint: sum of all bits in commitment row != 0 or 1
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (36, "transpose row constraint").into(),
                        1,
                        "Constrain transposition of bit",
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (26, "Transpose ship commitments").into(),
                        offset: 46,
                    },
                    cell_values: vec![
                        (((Any::Advice, 0).into(), 0).into(), String::from("1"),),
                        (((Any::Advice, 1).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 2).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 3).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 4).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 5).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 6).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 7).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 8).into(), 0).into(), String::from("0"),),
                        (((Any::Advice, 9).into(), 0).into(), String::from("1"),),
                    ]
                }
            ])
        );
    }

    #[test]
    fn invalid_board_commitment() {
        // prove the circuit will throw an error if the board commitment advice is not equal to the computed commitment
        // construct battleship board pattern #2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state and add one to the x coordinate to invalidate commitment
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned() + pallas::Base::one();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
            trapdoor,
        );
        // prove that attempting to place ships that collide vertically fails verification
        let prover = MockProver::run(12, &circuit, vec![commitment]).unwrap();
        // expect a permutation failure when the computed board hash does not match the advice given to the circuit
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Advice, 2).into(),
                    location: FailureLocation::InRegion {
                        region: (35, "complete point addition").into(),
                        offset: 1
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 0 }
                }
            ])
        );
    }

    #[test]
    fn production() {
        // construct valid battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            vec![x, y]
        };
        // construct Board circuit
        let circuit = BoardCircuit::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
            trapdoor,
        );
        // Initialize the polynomial commitment parameters
        let params: Params<vesta::Affine> = Params::new(12);
        // Initialize the proving key
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
        // create proof for verifier benchmark
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[&[&commitment]],
            &mut OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&commitment]],
            &mut transcript
        )
        .is_ok());
    }

    // #[test]
    // fn print_circuit() {
    //     use plotters::prelude::*;
    //     // construct battleship board pattern #1
    //     let board = Board::from(&Deck::from([
    //         Some((3, 3, true)),
    //         Some((5, 4, false)),
    //         Some((0, 1, false)),
    //         Some((0, 5, true)),
    //         Some((6, 1, false)),
    //     ]));
    //     // take the poseidon hash of the board state as the public board commitment
    //     // construct BoardValidity circuit
    //     let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
    //         board.witness(DEFAULT_WITNESS_OPTIONS),
    //         board.state(DEFAULT_WITNESS_OPTIONS),
    //     );
    //     let root =
    //         BitMapBackend::new("board_layout.png", (1920, 1080)).into_drawing_area();
    //     root.fill(&WHITE).unwrap();
    //     let root = root
    //         .titled("Board Circuit Layout", ("sans-serif", 60))
    //         .unwrap();
    //     CircuitLayout::default()
    //         // You can optionally render only a section of the circuit.
    //         .view_width(0..2)
    //         .view_height(0..16)
    //         // You can hide labels, which can be useful with smaller areas.
    //         .show_labels(false)
    //         // Render the circuit onto your area!
    //         // The first argument is the size parameter for the circuit.
    //         .render(15, &circuit, &root)
    //         .unwrap();
    // }
}
