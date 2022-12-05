use {
    crate::{
        board::{
            chip::{BoardChip, BoardConfig},
            gadget::BoardGadget,
        },
        utils::board::Board,
    },
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
};

#[derive(Debug, Clone, Copy)]
struct BoardCircuit<F: FieldExt> {
    pub gadget: BoardGadget<F>,
}

impl<F: FieldExt> Circuit<F> for BoardCircuit<F> {
    type Config = BoardConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        BoardChip::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        let chip = BoardChip::new(config);
        chip.synthesize(layouter, self.gadget)
    }
}

impl<F: FieldExt> BoardCircuit<F> {
    /**
     * Construct a new board circuit given a commitment to ship placements
     * @dev handles all trace/ gadget construction given deck input
     *
     * @param ships - assignments for each of 5 ships to place on a board
     * @return - instantiated BoardCircuit object containing BoardGadget
     */
    pub fn new(board: Board) -> BoardCircuit<F> {
        BoardCircuit {
            gadget: BoardGadget::new(board),
        }
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::utils::{
            board::{Board, Deck},
        },
        halo2_proofs::{
            dev::{CircuitLayout, MockProver},
            pasta::Fp,
        },
    };

    #[test]
    fn valid_0() {
        // construct valid battleship board
        let board = Board::from(&Deck::default());
        // construct BoardValidity circuit
        let circuit = BoardCircuit::<Fp>::new(board);
        let prover = MockProver::run(7, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn print_circuit() {
        use plotters::prelude::*;
        let board = Board::from(&Deck::default());
        let circuit = BoardCircuit::<Fp>::new(board);
        let root = BitMapBackend::new("src/board/board_layout.png", (1920, 1080))
            .into_drawing_area();
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
            .render(7, &circuit, &root)
            .unwrap();
    }
}
