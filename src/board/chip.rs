use {
    crate::{
        bits2num::bits2num::{Bits2NumChip, Bits2NumConfig},
        board::gadget::BoardGadget,
        utils::board::BOARD_SIZE,
    },
    halo2_proofs::{
        arithmetic::{lagrange_interpolate, Field, FieldExt},
        circuit::{AssignedCell, Chip, Layouter, Region},
        plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
        poly::Rotation,
    },
    std::marker::PhantomData,
};

/**
 * Contains all storage needed to verify a battleship board
 */
#[derive(Clone, Copy, Debug)]
pub struct BoardConfig<F: FieldExt> {
    pub bits2num: [Bits2NumConfig; 10],
    pub advice: [Column<Advice>; 10],
    pub selectors: [Selector; 1],
    _marker: PhantomData<F>,
}

/**
 * Circuit for proving a valid battleship board configuration
 *    * prove 5 types of ships placed correctly
 *    * prove public commitment is the signed poseidon hash of board integer
 */
pub struct BoardChip<F: FieldExt> {
    config: BoardConfig<F>,
}

impl<F: FieldExt> Chip<F> for BoardChip<F> {
    type Config = BoardConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/**
 * Instructions used by the board chip
 */
pub trait BoardInstructions<F: FieldExt> {
    /**
     * Load the 10 ship placement integer commitments into the advice column
     *
     * @param gadget - BoardGadget holding board util object
     */
    fn load_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
    ) -> Result<(), Error>;

    /**
     * Load each commitment into a bits2num chip to get constrained 100 bit decompositions
     *
     * @param gadget - BoardGadget storing cell assignments
     */
    fn decompose_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
    ) -> Result<(), Error>;
}

impl<F: FieldExt> BoardChip<F> {
    pub fn new(config: BoardConfig<F>) -> Self {
        BoardChip { config }
    }

    /**
     * Configure the computation space of the circuit & return BoardConfig
     */
    pub fn configure(meta: &mut ConstraintSystem<F>) -> BoardConfig<F> {
        // define advice
        let mut advice = Vec::<Column<Advice>>::new();
        for _ in 0..10 {
            let col = meta.advice_column();
            meta.enable_equality(col);
            advice.push(col);
        }
        let advice: [Column<Advice>; 10] = advice.try_into().unwrap();

        // define selectors
        let mut selectors = Vec::<Selector>::new();
        for _ in 0..1 {
            selectors.push(meta.selector());
        }
        let selectors: [Selector; 1] = selectors.try_into().unwrap();

        // define bits2num chips
        let mut bits2num = Vec::<Bits2NumConfig>::new();
        for _ in 0..10 {
            bits2num.push(Bits2NumChip::<_, BOARD_SIZE>::configure(meta));
        }
        let bits2num: [Bits2NumConfig; 10] = bits2num.try_into().unwrap();

        // define gates

        // return config
        BoardConfig {
            bits2num,
            advice,
            selectors,
            _marker: PhantomData,
        }
    }

    /**
     * Synthesize a proof of a valid board
     *
     * @param gadget - helper
     */
    pub fn synthesize(
        &self,
        mut layouter: impl Layouter<F>,
        gadget: BoardGadget<F>,
    ) -> Result<(), Error> {
    }
}

impl<F: FieldExt> BoardInstructions<F> for BoardChip<F> {
    fn load_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
    ) -> Result<[AssignedCell<F, F>; 10], Error> {
        let commitments = gadget.board.private_witness();
        let assigned: [AssignedCell<F, F>; 10] = layouter.assign_region(
            || "load ship placements",
            |mut region: Region<F>| {
                for i in 0..commitments.0.len() {
                    region.assign_advice(
                        || format!("placement commitment #{}", i),
                        self.config.advice[i],
                        0,
                        F::from_repr(commitments[i])
                    )
                }
                // let sum = region.assign_advice(
                //     || "sum of h & v placements",
                //     self.config.advice[0],
                //     0,
                //     || sum,
                // )?;
                Ok([sum, horizontal_cell.clone(), vertical_cell.clone()])
            },
        )?;
        Ok(assigned)
    }

    fn decompose_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
    ) -> Result<(), Error> {
    }
}
