use {
    crate::{
        shot::chip::{ShotChip, ShotConfig},
        utils::{binary::BinaryValue, shot::serialize},
    },
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, Column, Instance, ConstraintSystem, Error},
    },
    std::marker::PhantomData,
};

#[derive(Debug, Clone, Copy)]
struct ShotCircuit<F: FieldExt> {
    pub board: BinaryValue,
    pub shot: BinaryValue,
    pub hit: bool,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Circuit<F> for ShotCircuit<F> {
    type Config = ShotConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        ShotChip::configure(meta, instance)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        Ok(ShotChip::new(config).synthesize(layouter, self.board, self.shot, self.hit)?)
    }
}

impl<F: FieldExt> ShotCircuit<F> {
    /**
     * Construct a new shot circuit to evaluate whether a valid shot hits a ship
     *
     * @param board - private board placement
     * @param shot - x, y coordinates to serialize into a shot commitment
     * @param hit - assertion that the shot either hits or misses the decomposed board 
     * @return - instantiated BoardCircuit object containing BoardGadget
     */
    pub fn new(board: BinaryValue, shot: [u8; 2], hit: bool) -> ShotCircuit<F> {
        ShotCircuit {
            board,
            shot: serialize(shot[0], shot[1]),
            hit,
            _marker: PhantomData
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
    fn valid_hit_0() {
        // construct valid battleship board
        // let board = Board::from(&Deck::default());
        let board = Board::from(&Deck::from(
            [3, 5, 0, 0, 6],
            [3, 4, 1, 5, 1],
            [true, false, false, true, false],
        ));
        let shot = [3u8, 5];
        let hit = true;
        let public_inputs = vec![
            Fp::from_u128(board.state.lower_u128()),
            Fp::from_u128(serialize(shot[0], shot[1]).lower_u128()),
            Fp::from(hit)
        ];
        // construct BoardValidity circuit
        let circuit = ShotCircuit::<Fp>::new(board.state, shot, hit);
        let prover = MockProver::run(12, &circuit, vec![public_inputs]);
        assert_eq!(prover.unwrap().verify(), Ok(()));
    }

    // #[test]
    // fn print_circuit() {
    //     use plotters::prelude::*;
    //     let board = Board::from(&Deck::default());
    //     let circuit = BoardCircuit::<Fp>::new(board);
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
