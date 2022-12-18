use {
    crate::{
        board::chip::{BoardChip, BoardConfig},
        utils::board::Board,
    },
    halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3, Spec},
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    std::marker::PhantomData,
};

#[derive(Debug, Clone, Copy)]
struct BoardCircuit<S: Spec<F, 3, 2>, F: FieldExt> {
    pub board: Board,
    _field: PhantomData<F>,
    _spec: PhantomData<S>,
}

impl<S: Spec<F, 3, 2>, F: FieldExt> Circuit<F> for BoardCircuit<S, F> {
    type Config = BoardConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        // @TODO fix
        BoardCircuit::new(self.board)
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        BoardChip::<S, F>::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        let chip = BoardChip::<S, F>::new(config);
        chip.synthesize(layouter, self.board)
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
    pub fn new(board: Board) -> BoardCircuit<S, F> {
        BoardCircuit {
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
        crate::utils::board::{Board, Deck},
        halo2_proofs::{
            dev::{CircuitLayout, MockProver},
            pasta::Fp,
        },
    };

    #[test]
    fn valid_0() {
        let board = Board::from(&Deck::from(
            [3, 5, 0, 0, 6],
            [3, 4, 1, 5, 1],
            [true, false, false, true, false],
        ));
        let board_commitment = Hash::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(board);
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn valid_1() {
        // construct battleship board pattern #2
        let board = Board::from(&Deck::from(
            [3, 9, 0, 0, 6],
            [4, 6, 0, 6, 1],
            [false, true, false, false, true],
        ));
        let board_commitment = Hash::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init()
            .hash([Fp::from_u128(board.state.lower_u128())]);
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(board);
        let prover = MockProver::run(12, &circuit, vec![vec![board_commitment]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn print_circuit() {
        use plotters::prelude::*;
        let board = Board::from(&Deck::default());
        let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(board);
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
