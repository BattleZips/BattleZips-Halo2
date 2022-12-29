use {
    crate::{
        shot::chip::{ShotChip, ShotConfig},
        utils::binary::BinaryValue,
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
struct ShotCircuit<S: Spec<F, 3, 2>, F: FieldExt> {
    pub board: BinaryValue,
    pub shot: BinaryValue,
    pub hit: BinaryValue,
    _field: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec<F, 3, 2>, F: FieldExt> Circuit<F> for ShotCircuit<S, F> {
    type Config = ShotConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        // @TODO FIX
        ShotCircuit::new(self.board, self.shot, self.hit)
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        ShotChip::<S, F>::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        Ok(ShotChip::<S, F>::new(config).synthesize(layouter, self.board, self.shot, self.hit)?)
    }
}

impl<S: Spec<F, 3, 2>, F: FieldExt> ShotCircuit<S, F> {
    /**
     * Construct a new shot circuit to evaluate whether a valid shot hits a ship
     *
     * @param board - private board placement
     * @param shot - x, y coordinates serialized into a shot commitment
     * @param hit - assertion that the shot either hits or misses the decomposed board (constrained 0 or 1)
     * @return - instantiated BoardCircuit object containing BoardGadget
     */
    pub fn new(board: BinaryValue, shot: BinaryValue, hit: BinaryValue) -> ShotCircuit<S, F> {
        ShotCircuit {
            board,
            shot,
            hit,
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
            binary::U256, board::Board, deck::Deck, ship::DEFAULT_WITNESS_OPTIONS, shot::serialize,
        },
        halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as Poseidon, P128Pow5T3},
        halo2_proofs::{
            dev::{CircuitLayout, FailureLocation, MockProver, VerifyFailure},
            pasta::Fp,
            plonk::Any,
        },
    };

    #[test]
    fn valid_hit_0() {
        // construct valid battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, false)),
            Some((6, 1, true)),
        ]));
        let shot = serialize::<1>([3], [5]);
        let hit = BinaryValue::from_u8(1);
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        let public_inputs = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // construct BoardValidity circuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_inputs]);
        assert_eq!(prover.unwrap().verify(), Ok(()));
    }

    #[test]
    fn valid_hit_1() {
        // construct valid battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        let shot = serialize::<1>([9], [8]);
        let hit = BinaryValue::from_u8(1);
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        let public_inputs = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // construct BoardValidity circuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_inputs]);
        assert_eq!(prover.unwrap().verify(), Ok(()));
    }

    #[test]
    fn valid_miss_0() {
        // construct valid battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, false)),
            Some((6, 1, true)),
        ]));
        let shot = serialize::<1>([4], [3]);
        let hit = BinaryValue::from_u8(0);
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        let public_inputs = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // construct BoardValidity circuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_inputs]);
        assert_eq!(prover.unwrap().verify(), Ok(()));
    }

    #[test]
    fn valid_miss_1() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // make a shot that misses this board configuration
        let shot = serialize::<1>([3], [3]);
        // assert the shot misses
        let hit = BinaryValue::from_u8(0);
        // get the Poseidon hash of the board state
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove ShotCircuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]);
        assert_eq!(prover.unwrap().verify(), Ok(()));
    }

    #[test]
    fn invalid_non_boolean_hit_assertion() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // make a shot that hits this board configuration
        let shot = serialize::<1>([9], [8]);
        // assert a non-boolean value for hit
        let hit = BinaryValue::from_u8(2);
        // get the Poseidon hash of the board state
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove ShotCircuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::ConstraintNotSatisfied {
                    // check violation of boolean input constraint
                    constraint: (
                        (5, "boolean hit assertion").into(),
                        0,
                        "asserted hit value is boolean"
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (0, "load private ShotChip advice values").into(),
                        offset: 3
                    },
                    cell_values: vec![(((Any::Advice, 4).into(), 0).into(), String::from("0x2"))]
                },
                VerifyFailure::ConstraintNotSatisfied {
                    // counted counted hit # does not match asserted hit #
                    constraint: (
                        (7, "constrain shot running sum output").into(),
                        1,
                        "Public hit assertion matches private witness"
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (4, "shot running sum output checks").into(),
                        offset: 0
                    },
                    cell_values: vec![
                        (((Any::Advice, 0).into(), 0).into(), String::from("0x2")),
                        (((Any::Advice, 2).into(), 0).into(), String::from("1"))
                    ]
                }
            ])
        );
    }

    #[test]
    fn invalid_assert_hit_when_miss() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // make a shot that misses this board configuration
        let shot = serialize::<1>([8], [8]);
        // assert that this shot hits the board configuration
        let hit = BinaryValue::from_u8(1);
        // get the Poseidon hash of the board state
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove ShotCircuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                // fail constraint: count 0 hits but 1 inputted
                constraint: (
                    (7, "constrain shot running sum output").into(),
                    1,
                    "Public hit assertion matches private witness"
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (4, "shot running sum output checks").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::Advice, 0).into(), 0).into(), String::from("1")),
                    (((Any::Advice, 2).into(), 0).into(), String::from("0"))
                ]
            }])
        );
    }

    #[test]
    fn invalid_assert_miss_when_hit() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, false)),
            Some((6, 1, true)),
        ]));
        // make a shot that misses this board configuration
        let shot = serialize::<1>([6], [2]);
        // assert that this shot hits the board configuration
        let hit = BinaryValue::from_u8(0);
        // get the Poseidon hash of the board state
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove ShotCircuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                // fail constraint: count 1 hits but 0 inputted
                constraint: (
                    (7, "constrain shot running sum output").into(),
                    1,
                    "Public hit assertion matches private witness"
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (4, "shot running sum output checks").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::Advice, 0).into(), 0).into(), String::from("0")),
                    (((Any::Advice, 2).into(), 0).into(), String::from("1"))
                ]
            }])
        );
    }

    #[test]
    fn invalid_no_shot() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, false)),
            Some((6, 1, true)),
        ]));
        // make a shot that misses this board configuration
        let shot = BinaryValue::new(U256::from([0, 0, 0, 0]));
        // assert that this shot misses the board configuration
        let hit = BinaryValue::from_u8(0);
        // get the Poseidon hash of the board state
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove ShotCircuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                // fail constraint: 0 shots counted when 1 expected
                constraint: (
                    (7, "constrain shot running sum output").into(),
                    0,
                    "Shot only fires at one board cell"
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (4, "shot running sum output checks").into(),
                    offset: 0
                },
                cell_values: vec![(((Any::Advice, 1).into(), 0).into(), String::from("0")),]
            }])
        );
    }

    #[test]
    fn invalid_multi_shot() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, false)),
            Some((6, 1, true)),
        ]));
        // make one shot that misses and one that hits in a single commitment
        let shot = serialize::<2>([3, 9], [3, 9]);
        // assert that this shot hits the board configuration
        let hit = BinaryValue::from_u8(1);
        // get the Poseidon hash of the board state
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove ShotCircuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                // fail constraint: 2 shots counted when 1 expected
                constraint: (
                    (7, "constrain shot running sum output").into(),
                    0,
                    "Shot only fires at one board cell"
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (4, "shot running sum output checks").into(),
                    offset: 0
                },
                cell_values: vec![(((Any::Advice, 1).into(), 0).into(), String::from("0x2")),]
            }])
        );
    }

    #[test]
    fn invalid_multi_hit() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // make three shots that all hit
        let shot = serialize::<3>([0, 1, 2], [0, 0, 0]);
        // assert that this shot hits the board configuration
        // @dev could either constrain this way which will count wrong # of hits, or nonzero hit assertion
        let hit = BinaryValue::from_u8(1);
        // get the Poseidon hash of the board state
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove ShotCircuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::ConstraintNotSatisfied {
                    // fail constraint: 3 shots counted when 1 expected
                    constraint: (
                        (7, "constrain shot running sum output").into(),
                        0,
                        "Shot only fires at one board cell"
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (4, "shot running sum output checks").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::Advice, 1).into(), 0).into(), String::from("0x3")),]
                },
                VerifyFailure::ConstraintNotSatisfied {
                    // fail constraint: count 1 hits but 0 inputted
                    constraint: (
                        (7, "constrain shot running sum output").into(),
                        1,
                        "Public hit assertion matches private witness"
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (4, "shot running sum output checks").into(),
                        offset: 0
                    },
                    cell_values: vec![
                        (((Any::Advice, 0).into(), 0).into(), String::from("1")),
                        (((Any::Advice, 2).into(), 0).into(), String::from("0x3"))
                    ]
                }
            ])
        );
    }

    #[test]
    fn invalid_hash() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // make a shot that hits the board configuration
        let shot = serialize::<1>([0], [0]);
        // assert that this shot hits the board configuration
        let hit = BinaryValue::from_u8(1);
        // get the Poseidon hash of the board state AND ADD ONE to make it incorrect
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]) + Fp::one();
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove ShotCircuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Advice, 0).into(),
                    location: FailureLocation::InRegion {
                        region: (7, "permute state").into(),
                        offset: 36
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
    fn invalid_public_board_commitment() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, false)),
            Some((6, 1, true)),
        ]));
        // make a shot that misses the board configuration
        let shot = serialize::<1>([0], [0]);
        // assert that this shot misses the board configuration
        let hit = BinaryValue::from_u8(0);
        // get the Poseidon hash of the board state
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // specify the public exports from the proof
        // add one to public_exports[0] to throw off publicly asserted board commitment
        let public_exports = vec![
            hashed + Fp::one(),
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove ShotCircuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Advice, 0).into(),
                    location: FailureLocation::InRegion {
                        region: (7, "permute state").into(),
                        offset: 36
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
    fn invalid_public_shot_commitment() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, false)),
            Some((6, 1, true)),
        ]));
        // make a shot that misses the board configuration
        let shot = serialize::<1>([0], [0]);
        // assert that this shot misses the board configuration
        let hit = BinaryValue::from_u8(0);
        // get the Poseidon hash of the board state
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // specify the public exports from the proof
        // add one to public_exports[1] to throw off publicly asserted shot commitment
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()) + Fp::one(),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove ShotCircuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Advice, 4).into(),
                    location: FailureLocation::InRegion {
                        region: (0, "load private ShotChip advice values").into(),
                        offset: 2
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 1 }
                }
            ])
        );
    }

    #[test]
    fn invalid_public_hit_assertion() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, false)),
            Some((6, 1, true)),
        ]));
        // make a shot that hits the board configuration
        let shot = serialize::<1>([1], [6]);
        // assert that this shot hits the board configuration
        let hit = BinaryValue::from_u8(1);
        // get the Poseidon hash of the board state
        let hashed =
            Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
                board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
            )]);
        // specify the public exports from the proof
        // add one to public_exports[2] to throw off public hit assertion
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()) + Fp::one(),
        ];
        // mock prove ShotCircuit
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (7, "constrain shot running sum output").into(),
                        1,
                        "Public hit assertion matches private witness"
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (4, "shot running sum output checks").into(),
                        offset: 0
                    },
                    cell_values: vec![
                        (((Any::Advice, 0).into(), 0).into(), String::from("1")),
                        (((Any::Advice, 2).into(), 0).into(), String::from("0")),
                    ]
                },
                VerifyFailure::Permutation {
                    column: (Any::Advice, 4).into(),
                    location: FailureLocation::InRegion {
                        region: (0, "load private ShotChip advice values").into(),
                        offset: 3
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                }
            ])
        );
    }

    #[test]
    fn print_circuit() {
        use plotters::prelude::*;
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        let shot = serialize::<1>([1], [6]);
        let hit = BinaryValue::from_u8(1);
        let circuit =
            ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
        let root = BitMapBackend::new("src/shot/shot_layout.png", (1920, 1080)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Shot Circuit Layout", ("sans-serif", 60))
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
