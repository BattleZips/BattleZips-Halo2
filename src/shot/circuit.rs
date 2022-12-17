use {
    crate::{
        shot::chip::{ShotChip, ShotConfig},
        utils::{binary::BinaryValue, shot::serialize},
    },
    halo2_gadgets::poseidon::primitives::{P128Pow5T3, Spec},
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
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
    use std::fmt::Binary;

    use {
        super::*,
        crate::utils::board::{Board, Deck},
        halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as Poseidon},
        halo2_proofs::{
            dev::{CircuitLayout, FailureLocation, MockProver, VerifyFailure},
            pasta::Fp,
            plonk::Any,
        },
    };

    #[test]
    fn valid_hit_0() {
        // construct valid battleship board pattern 1
        let board = Board::from(&Deck::from(
            [3, 5, 0, 0, 6],
            [3, 4, 1, 5, 1],
            [true, false, false, true, false],
        ));
        let shot = serialize(3u8, 5);
        let hit = BinaryValue::from_u8(1);
        let hashed = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        let public_inputs = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // construct BoardValidity circuit
        let circuit = ShotCircuit::<P128Pow5T3, Fp>::new(board.state, shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_inputs]);
        assert_eq!(prover.unwrap().verify(), Ok(()));
    }

    #[test]
    fn valid_hit_1() {
        // construct valid battleship board pattern 2
        let board = Board::from(&Deck::from(
            [3, 9, 0, 0, 6],
            [4, 6, 0, 6, 1],
            [false, true, false, false, true],
        ));
        let shot = serialize(9, 8);
        let hit = BinaryValue::from_u8(1);
        let hashed = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        let public_inputs = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // construct BoardValidity circuit
        let circuit = ShotCircuit::<P128Pow5T3, Fp>::new(board.state, shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_inputs]);
        assert_eq!(prover.unwrap().verify(), Ok(()));
    }

    #[test]
    fn valid_miss_0() {
        // construct valid battleship board pattern 1
        let board = Board::from(&Deck::from(
            [3, 5, 0, 0, 6],
            [3, 4, 1, 5, 1],
            [true, false, false, true, false],
        ));
        let shot = serialize(4, 3);
        let hit = BinaryValue::from_u8(0);
        let hashed = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        let public_inputs = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // construct BoardValidity circuit
        let circuit = ShotCircuit::<P128Pow5T3, Fp>::new(board.state, shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_inputs]);
        assert_eq!(prover.unwrap().verify(), Ok(()));
    }

    #[test]
    fn valid_miss_1() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from(
            [3, 9, 0, 0, 6],
            [4, 6, 0, 6, 1],
            [false, true, false, false, true],
        ));
        // make a shot that misses this board configuration
        let shot = serialize(3, 3);
        // assert the shot misses
        let hit = BinaryValue::from_u8(0);
        // get the Poseidon hash of the board state
        let hashed = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove BoardCircuit
        let circuit = ShotCircuit::<P128Pow5T3, Fp>::new(board.state, shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]);
        assert_eq!(prover.unwrap().verify(), Ok(()));
    }

    #[test]
    fn invalid_non_boolean_hit_assertion() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from(
            [3, 9, 0, 0, 6],
            [4, 6, 0, 6, 1],
            [false, true, false, false, true],
        ));
        // make a shot that hits this board configuration
        let shot = serialize(9, 8);
        // assert a non-boolean value for hit
        let hit = BinaryValue::from_u8(2);
        // get the Poseidon hash of the board state
        let hashed = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove BoardCircuit
        let circuit = ShotCircuit::<P128Pow5T3, Fp>::new(board.state, shot, hit);
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
        let board = Board::from(&Deck::from(
            [3, 9, 0, 0, 6],
            [4, 6, 0, 6, 1],
            [false, true, false, false, true],
        ));
        // make a shot that misses this board configuration
        let shot = serialize(8, 8);
        // assert that this shot hits the board configuration
        let hit = BinaryValue::from_u8(1);
        // get the Poseidon hash of the board state
        let hashed = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove BoardCircuit
        let circuit = ShotCircuit::<P128Pow5T3, Fp>::new(board.state, shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(prover.verify(), Err(vec![
            VerifyFailure::ConstraintNotSatisfied {
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
            }
        ]));
    }
    
    #[test]
    fn invalid_assert_miss_when_hit() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from(
            [3, 5, 0, 0, 6],
            [3, 4, 1, 5, 1],
            [true, false, false, true, false],
        ));
        // make a shot that misses this board configuration
        let shot = serialize(7, 1);
        // assert that this shot hits the board configuration
        let hit = BinaryValue::from_u8(0);
        // get the Poseidon hash of the board state
        let hashed = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        // specify the public exports from the proof
        let public_exports = vec![
            hashed,
            Fp::from_u128(shot.lower_u128()),
            Fp::from_u128(hit.lower_u128()),
        ];
        // mock prove BoardCircuit
        let circuit = ShotCircuit::<P128Pow5T3, Fp>::new(board.state, shot, hit);
        let prover = MockProver::run(9, &circuit, vec![public_exports]).unwrap();
        // expect failure
        assert_eq!(prover.verify(), Err(vec![
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
                    (((Any::Advice, 0).into(), 0).into(), String::from("0")),
                    (((Any::Advice, 2).into(), 0).into(), String::from("1"))
                ]
            }
        ]));
    }
    // #[test]
    // fn print_circuit() {
    //     use plotters::prelude::*;
    //     let board = Board::from(&Deck::from(
    //         [3, 5, 0, 0, 6],
    //         [3, 4, 1, 5, 1],
    //         [true, false, false, true, false],
    //     ));
    //     let shot = [3u8, 5];
    //     let hit = true;
    //     // construct BoardValidity circuit
    //     let circuit = ShotCircuit::<P128Pow5T3, Fp>::new(board.state, shot, hit);
    //     let root =
    //         BitMapBackend::new("src/shot/shot_layout.png", (1920, 1080)).into_drawing_area();
    //     root.fill(&WHITE).unwrap();
    //     let root = root
    //         .titled("Shot Circuit Layout", ("sans-serif", 60))
    //         .unwrap();

    //     CircuitLayout::default()
    //         // You can optionally render only a section of the circuit.
    //         .view_width(0..2)
    //         .view_height(0..16)
    //         // You can hide labels, which can be useful with smaller areas.
    //         .show_labels(false)
    //         // Render the circuit onto your area!
    //         // The first argument is the size parameter for the circuit.
    //         .render(12, &circuit, &root)
    //         .unwrap();
    // }
}
