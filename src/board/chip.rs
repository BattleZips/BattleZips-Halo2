use {
    crate::{
        bits2num::bits2num::{Bits2NumChip, Bits2NumConfig},
        board::{
            gadget::{BoardGadget, Placements, Commitments},
            primitives::placement::PlacementBits
        },
        utils::board::BOARD_SIZE,
    },
    halo2_proofs::{
        arithmetic::{lagrange_interpolate, Field, FieldExt},
        circuit::{AssignedCell, Chip, Layouter, Region, Value},
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
    ) -> Result<Commitments<F>, Error>;

    /**
     * Load each commitment into a bits2num chip to get constrained 100 bit decompositions
     *
     * @param gadget - BoardGadget functionality
     * @param commitments - assigned cells of commitments
     */
    fn decompose_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
        commitment: &[AssignedCell<F, F>; 10]
    ) -> Result<Placements<F>, Error>;
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
        let commitments = self.load_commitments(&mut layouter, gadget)?;
        _ = self.decompose_commitments(&mut layouter, gadget, &commitments);
        Ok(())
    }
}

impl<F: FieldExt> BoardInstructions<F> for BoardChip<F> {
    fn load_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
    ) -> Result<Commitments<F>, Error> {
        let commitments = gadget.private_witness();
        let assigned: [AssignedCell<F, F>; 10] = layouter.assign_region(
            || "load ship placements",
            |mut region: Region<F>| {
                let mut cells = Vec::<AssignedCell<F, F>>::new();
                for i in 0..10 {
                    let label = BoardGadget::<F>::commitment_label(i);
                    cells.push(region.assign_advice(
                        || format!("{} placement commitment", label),
                        self.config.advice[i],
                        0,
                        || Value::known(commitments[i])
                    )?);
                }
                Ok(cells.try_into().unwrap())
            },
        )?;
        Ok(assigned)
    }

    fn decompose_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
        commitments: &[AssignedCell<F, F>; 10]
    ) -> Result<Placements<F>, Error> {
        let bits = gadget.decompose_bits();
        let mut placements = Vec::<PlacementBits<F>>::new();
        for i in 0..10 {
            let bits2num = Bits2NumChip::<F, BOARD_SIZE>::new(commitments[i].clone(), bits[i]);
            let label = BoardGadget::<F>::commitment_label(i);
            let assigned_bits = bits2num.synthesize(
                self.config.bits2num[i],
                layouter.namespace(|| format!("{} bits2num", label))
            )?;
            placements.push(PlacementBits::<F>::from(assigned_bits));
        };
        Ok(placements.try_into().unwrap())
    }
}
