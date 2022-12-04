use {
    crate::{
        bits2num::bits2num::{Bits2NumChip, Bits2NumConfig},
        placement::gadget::PlacementBits,
        utils::{
            ship::{PlacementUtilities, ShipPlacement},
            board::BOARD_SIZE
        },
    },
    halo2_proofs::{
        arithmetic::{lagrange_interpolate, FieldExt},
        circuit::{AssignedCell, Chip, Layouter, Region},
        plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
        poly::Rotation,
    },
    std::marker::PhantomData,
};

/**
 * Takes an input of 
 * @dev ex: if coordinate = 19 and z = 1, then coordinate = 91
 */
#[derive(Clone, Copy, Debug)]
pub struct TransposeConfig<F: FieldExt> {
    pub bits2num: [Bits2NumConfig; 10],
    pub placements: [Column<Advice>; 10],
    // pub trace: [Column];
    pub selector: Selector,
    _marker: PhantomData<F>,
}

pub struct TransposeChip<F: FieldExt> {
    config: TransposeConfig<F, S>,
}

impl<F: FieldExt> Chip<F> for TransposeChip<F> {
    type Config = TransposeConfig<F, S>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> TransposeChip<F> {
    pub fn new(config: TransposeConfig<F>) -> Self {
        TransposeChip { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> TransposeConfig<F> {
        // define advice
        let mut advice = Vec::<Column<Advice>>::new();
        for _ in 0..2 {
            let col = meta.advice_column();
            meta.enable_equality(col);
            advice.push(col);
        }
        let advice: [Column<Advice>; 2] = advice.try_into().unwrap();

        // define selectors
        let selector = meta.selector();

        meta.create
    }

    // pub fn synth
}

/**
 * Utilities to assist in the assignment of ship placements
 */
pub trait TransposeUtilities<F: FieldExt> {

    /**
     * Permute 100 bits each from 10 bits2num chips into a single region
     */
    fn assign_placements(region: &mut Region<F>, placements: [PlacementBits<F>; 10]) -> Result<(), String>;

    fn permute(from: &PlacementBits<F>, to: &mut Column<Advice>) -> Result<(), String>;

    fn permute_transpose(from: &PlacementBits<F>, to: &mut Column<Advice>) -> Result<(), String>;

}

// impl<F: FieldExt> TransposeUtilities
