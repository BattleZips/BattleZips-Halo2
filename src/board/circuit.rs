use {
    crate::{
        board::chip::{BoardChip, BoardConfig},
        utils::{binary::BinaryValue, board::Board},
    },
    halo2_gadgets::poseidon::primitives::Spec,
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    std::marker::PhantomData,
};

#[derive(Debug, Clone, Copy)]
struct BoardCircuit<S: Spec<F, 3, 2>, F: FieldExt> {
    pub ship_commitments: [BinaryValue; 10],
    pub board: BinaryValue,
    _field: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec<F, 3, 2>, F: FieldExt> Circuit<F> for BoardCircuit<S, F> {
    type Config = BoardConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        // @TODO fix
        BoardCircuit::new(self.ship_commitments, self.board)
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        BoardChip::<S, F>::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        let chip = BoardChip::<S, F>::new(config);
        chip.synthesize(layouter, self.ship_commitments, self.board)
    }
}

impl<S: Spec<F, 3, 2>, F: FieldExt> BoardCircuit<S, F> {
    /**
     * Construct a new board circuit given a commitment to ship placements
     * @dev handles all trace/ gadget construction given deck input
     *
     * @param ships - assignments for each of 5 ships to place on a board
     * @return - instantiated BoardCircuit object containing BoardGadget
     */
    pub fn new(ship_commitments: [BinaryValue; 10], board: BinaryValue) -> BoardCircuit<S, F> {
        BoardCircuit {
            ship_commitments,
            board,
            _field: PhantomData,
            _spec: PhantomData,
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
            ship::{WitnessOption, DEFAULT_WITNESS_OPTIONS},
        },
        halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as Poseidon, P128Pow5T3},
        halo2_proofs::{
            dev::{CircuitLayout, FailureLocation, MockProver, VerifyFailure},
            pasta::Fp,
            plonk::Any,
        },
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
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
        );
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expect proof success
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
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
        );
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expect proof success
        assert_eq!(prover.verify(), Ok(()));
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
        let shot_commitments = board.witness(witness_options);
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state(witness_options).lower_u128())]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            shot_commitments,
            board.state(DEFAULT_WITNESS_OPTIONS),
        );
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expected failure constraint: either horizontal or vertical placement is 0
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (40, "Commitment orientation H OR V == 0 constraint").into(),
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
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            shot_commitments,
            board.state(DEFAULT_WITNESS_OPTIONS),
        );
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expect proof failure
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
        let shot_commitments = board.witness(witness_options);
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state(witness_options).lower_u128())]);
        // construct BoardValidity circuit
        let circuit =
            BoardCircuit::<P128Pow5T3, Fp>::new(shot_commitments, board.state(witness_options));
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expected failure constraint: cannot find a full ship placement bit window
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
        let shot_commitments = board.witness(witness_options);
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state(witness_options).lower_u128())]);
        // construct BoardValidity circuit
        let circuit =
            BoardCircuit::<P128Pow5T3, Fp>::new(shot_commitments, board.state(witness_options));
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expected failure constraint: either horizontal or vertical placement is 0
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
        let shot_commitments = board.witness(witness_options);
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state(witness_options).lower_u128())]);
        // construct BoardValidity circuit
        let circuit =
            BoardCircuit::<P128Pow5T3, Fp>::new(shot_commitments, board.state(witness_options));
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expected failure constraint: too many bits; too many full bit windows
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
        let shot_commitments = board.witness(witness_options);
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state(witness_options).lower_u128())]);
        // construct BoardValidity circuit
        let circuit =
            BoardCircuit::<P128Pow5T3, Fp>::new(shot_commitments, board.state(witness_options));
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expected failure constraint: too many bits; too many full bit windows
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
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
        );
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expected failure constraint: no full bit window found since consecutive bits are not in the same row
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
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
        );
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expected failure constraint: no full bit window found since consecutive bits are not in the same row
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
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
        );
        // expected failure constraint: more than 2 bits found in a transpose row, sum of all commitment bits in row != transposed commitment bit
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
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
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
        );
        // expected failure constraint: more than 2 bits found in a transpose row, sum of all commitment bits in row != transposed commitment bit
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
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
    fn invalid_board_commitment_advice() {
        // prove the circuit will throw an error if the board commitment advice is not equal to the computed commitment
        // construct battleship board pattern #2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // take the poseidon hash of the board state as the public board commitment, and add one to it to make it invalid
        let board_commitment =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]) + Fp::one();
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
        );
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expect a permutation failure when the computed board hash does not match the advice given to the circuit
        assert_eq!(prover.verify(), Err(vec![
            VerifyFailure::Permutation {
                column: (Any::Advice, 0).into(),
                location: FailureLocation::InRegion {
                    region: (30, "permute state").into(),
                    offset: 36
                }
            },
            VerifyFailure::Permutation {
                column: (Any::Instance, 0).into(),
                location: FailureLocation::OutsideRegion { row: 0 }
            }
        ]));
    }

    #[test]
    fn invalid_board_commitment_instance() {
        // prove the circuit will throw an error if a correct board commitment is given as advice,
        //      but a different commitment was given for the public instance output
        // construct battleship board pattern #1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
        );
        // add one to the public board commitment to make it invalid
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment + Fp::one()]]).unwrap();
        // expect a permutation failure when the computed board hash does not match the advice given to the circuit
        assert_eq!(prover.verify(), Err(vec![
            VerifyFailure::Permutation {
                column: (Any::Advice, 0).into(),
                location: FailureLocation::InRegion {
                    region: (30, "permute state").into(),
                    offset: 36
                }
            },
            VerifyFailure::Permutation {
                column: (Any::Instance, 0).into(),
                location: FailureLocation::OutsideRegion { row: 0 }
            }
        ]));
    }
    
    #[test]
    fn print_circuit() {
        use plotters::prelude::*;
        // construct battleship board pattern #1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // take the poseidon hash of the board state as the public board commitment
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state(DEFAULT_WITNESS_OPTIONS),
        );
        let root =
            BitMapBackend::new("src/board/board_layout.png", (1920, 1080)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Placement Circuit Layout", ("sans-serif", 60))
            .unwrap();

        CircuitLayout::default()
            // You can optionally render only a section of the circuit.
            .view_width(0..2)
            .view_height(0..16)
            // You can hide labels, which can be useful with smaller areas.
            .show_labels(false)
            // Render the circuit onto your area!
            // The first argument is the size parameter for the circuit.
            .render(12, &circuit, &root)
            .unwrap();
    }
}
