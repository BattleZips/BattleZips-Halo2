use {
    crate::{
        bitify::bitify::{BitifyConfig, Bits2NumChip},
        board::gadget::Placements,
        placement::gadget::PlacementBits,
        utils::board::BOARD_SIZE,
    },
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{AssignedCell, Chip, Layouter, Region, Value},
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
    pub bits2num: BitifyConfig, // bits2num to constrain output commitment
    pub advice: [Column<Advice>; 11], //0-9: permuted bits; 10: transposed bit
    pub selectors: [Selector; 2],
    _marker: PhantomData<F>,
}

pub struct TransposeChip<F: FieldExt> {
    config: TransposeConfig<F>,
}

impl<F: FieldExt> Chip<F> for TransposeChip<F> {
    type Config = TransposeConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/**
 * Chip instructions for constructing different regions
 */
pub trait TransposeInstructions<F: FieldExt> {
    /**
     * Copy decomposed bits from the 10 bits2num chips used in BoardValidity chip & assign transposed bit decomposition
     * @notice transposes odd-index placements (vertical) by reversing 10^0 and 10^1 in serialization
     *
     * @param placements - references to 10x100 assigned cells of bit decompositions for private ship commitments
     * @param transposed - array of 100 bits representing transposed bit commitments
     * @return - reference to assigned cells of transposed bit column
     */
    fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        placements: Placements<F>,
        transposed: [F; BOARD_SIZE],
    ) -> Result<PlacementBits<F>, Error>;
}

impl<F: FieldExt> TransposeChip<F> {
    pub fn new(config: TransposeConfig<F>) -> Self {
        TransposeChip { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> TransposeConfig<F> {
        // define advice
        let mut advice = Vec::<Column<Advice>>::new();
        for _ in 0..11 {
            let col = meta.advice_column();
            meta.enable_equality(col);
            advice.push(col);
        }
        let advice: [Column<Advice>; 11] = advice.try_into().unwrap();

        // define selectors
        let mut selectors = Vec::<Selector>::new();
        for _ in 0..2 {
            selectors.push(meta.selector());
        }
        let selectors: [Selector; 2] = selectors.try_into().unwrap();

        // define transposed bits2num config
        let bits2num = Bits2NumChip::<_, BOARD_SIZE>::configure(meta);

        meta.create_gate("transpose row constraint", |meta| {
            // constrain a transpose row
            // advice[0..10] == advice[10]
            // advice[10] == 0 or 1
            let zero = Expression::Constant(F::zero());
            let one = Expression::Constant(F::one());
            let mut transposed_bit = zero;
            for i in 0..10 {
                transposed_bit =
                    transposed_bit.clone() + meta.query_advice(advice[i], Rotation::cur());
            }
            let transposed_trace = meta.query_advice(advice[10], Rotation::cur());
            let selector = meta.query_selector(selectors[0]);
            Constraints::with_selector(
                selector,
                [
                    (
                        "Constrain trace value integrity",
                        transposed_trace.clone() - transposed_bit.clone(),
                    ),
                    (
                        "Constrain transposition of bit",
                        (one - transposed_bit.clone()) * transposed_bit.clone(),
                    ),
                ],
            )
        });

        meta.create_gate("transposed commitment decomposition constraint", |meta| {
            let transposed = meta.query_advice(advice[0], Rotation::cur());
            let committed = meta.query_advice(advice[0], Rotation::cur());
            let selector = meta.query_selector(selectors[1]);
            Constraints::with_selector(
                selector,
                [(
                    "Constrain decomposed commitment bit == transposed bit",
                    transposed - committed,
                )],
            )
        });

        TransposeConfig {
            bits2num,
            advice,
            selectors,
            _marker: PhantomData,
        }
    }

    /**
     * Synthesize a new transposition of ship commitments into one board
     * @todo add bits2num constraint on final commitment
     *
     * @param commitment - the inputted transposed board commitment value
     * @param bits - the binary decomposition of the commitment on field
     * @param placements - reference to bits2num chips' decomposed ship commitments
     * @return - reference to the constrained (recomposed) transposed commitment to board states
     */
    pub fn synthesize(
        &self,
        layouter: &mut impl Layouter<F>,
        commitment: F,
        bits: [F; BOARD_SIZE],
        placements: Placements<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let transposed = self.load(layouter, placements, bits)?;
        let bits2num = Bits2NumChip::<F, BOARD_SIZE>::new(commitment, transposed.0);
        let commitment = bits2num.synthesize(
            self.config.bits2num,
            layouter.namespace(|| "decompose transposed commitment"),
        )?;
        Ok(commitment.clone())
    }
}

impl<F: FieldExt> TransposeInstructions<F> for TransposeChip<F> {
    fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        placements: Placements<F>,
        transposed: [F; BOARD_SIZE],
    ) -> Result<PlacementBits<F>, Error> {
        Ok(layouter.assign_region(
            || "Transpose ship commitments",
            |mut region: Region<F>| {
                // permute from bits2num chips
                for i in 0..10 {
                    for j in 0..BOARD_SIZE {
                        let transposed_index = if i % 2 == 1 { j % 10 * 10 + j / 10 } else { j };
                        let orientation = if i % 2 == 1 { "vertical" } else { "horizontal" };
                        placements[i].0[transposed_index].clone().copy_advice(
                            || format!("permute {} ship {} bit {}", orientation, i / 2, j),
                            &mut region,
                            self.config.advice[i],
                            j,
                        )?;
                    }
                }
                // assign transposed commitment
                let mut assigned = Vec::<AssignedCell<F, F>>::new();
                for i in 0..BOARD_SIZE {
                    assigned.push(region.assign_advice(
                        || format!("assign tranposed bit {}", i),
                        self.config.advice[10],
                        i,
                        || Value::known(transposed[i].clone()),
                    )?);
                    // toggle transposed row constraint
                    self.config.selectors[0].enable(&mut region, i)?;
                }
                Ok(PlacementBits::<F>::from(assigned.try_into().unwrap()))
            },
        )?)
    }
}