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

    use crate::utils::shot::serialize;

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
            Some((3, 5, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state,
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
        let board_commitment = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
            board.witness(DEFAULT_WITNESS_OPTIONS),
            board.state,
        );
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expect proof success
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn invalid_placement_dual() {
        // construct battleship board pattern #2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        // modify the shot_commitment for H5, V5 by setting horizontal as expected and vertical = 1 (not allowed)
        let mut shot_commitments = board.witness(DEFAULT_WITNESS_OPTIONS);
        // define a commitment that will not intersect with other ships and cause further constrains
        shot_commitments[1] = serialize::<1>([6], [6]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(shot_commitments, board.state);
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expected failure constraint: either horizontal or vertical placement is 0
        let expected = VerifyFailure::ConstraintNotSatisfied {
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
                    String::from("0xf80000000000"),
                ),
                (
                    ((Any::Advice, 1).into(), 0).into(),
                    String::from("0x40000000000000000"),
                ),
            ],
        };
        println!("xx: {:?}", prover.verify().unwrap_err());
        // assert!(prover.verify().unwrap_err().contains(&expected));
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
        // take the poseidon hash of the board state as the public board commitment
        let board_commitment = Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        // modify the shot_commitment for H5, V5 by setting both equal to 0
        let mut shot_commitments = board.witness(DEFAULT_WITNESS_OPTIONS);
        shot_commitments[1] = BinaryValue::from_u8(0);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(shot_commitments, board.state);
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        // expect proof failure
        assert_eq!(
            prover.verify(),
            Err(vec![
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

    // #[test]
    // fn invalid_placement_consecutive_bits() {
    //     // @TODO: test for correct # of bits included but
    // }

    // #[test]
    // fn print_circuit() {
    //     use plotters::prelude::*;
    //     let orientation = [false, false, false, false, false];
    //     let board = Board::from(&Deck::default());
    //     let circuit =
    //         BoardCircuit::<P128Pow5T3, Fp>::new(board.witness(), orientation, board.state);
    //     let root =
    //         BitMapBackend::new("src/board/board_layout.png", (1920, 1080)).into_drawing_area();
    //     root.fill(&WHITE).unwrap();
    //     let root = root
    //         .titled("Placement Circuit Layout", ("sans-serif", 60))
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
