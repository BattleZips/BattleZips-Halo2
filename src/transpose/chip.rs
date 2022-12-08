use {
    crate::utils::board::BOARD_SIZE,
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
    pub permuted_bits: [Column<Advice>; 10],
    pub transposed_bits: Column<Advice>,
    pub selector: Selector, // constrains the transposition of row of all ship bits into a single board bit
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

impl<F: FieldExt> TransposeChip<F> {
    pub fn new(config: TransposeConfig<F>) -> Self {
        TransposeChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        permuted_bits: [Column<Advice>; 10],
        transposed_bits: Column<Advice>,
    ) -> TransposeConfig<F> {
        // define selectors
        let selector = meta.selector();

        meta.create_gate("transpose row constraint", |meta| {
            // constrain a transpose row
            // sum(permuted_bits[i]) == transposed_bits[i]
            // advice[10] == 0 or 1
            let zero = Expression::Constant(F::zero());
            let one = Expression::Constant(F::one());
            let mut transposed_bit = zero;
            for i in 0..10 {
                transposed_bit =
                    transposed_bit.clone() + meta.query_advice(permuted_bits[i], Rotation::cur());
            }
            let transposed_trace = meta.query_advice(transposed_bits, Rotation::cur());
            let selector = meta.query_selector(selector);
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

        TransposeConfig {
            permuted_bits,
            transposed_bits,
            selector,
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
        placements: [[AssignedCell<F, F>; BOARD_SIZE]; 10],
    ) -> Result<[AssignedCell<F, F>; BOARD_SIZE], Error> {
        Ok(layouter
            .assign_region(
                || "Transpose ship commitments",
                |mut region: Region<F>| {
                    // permute from bits2num chips
                    for col in 0..10 {
                        for row in 0..BOARD_SIZE {
                            let transposed_index = if col % 2 == 1 {
                                row % 10 * 10 + row / 10
                            } else {
                                row
                            };
                            let orientation = if col % 2 == 1 {
                                "vertical"
                            } else {
                                "horizontal"
                            };
                            placements[col][transposed_index].clone().copy_advice(
                                || format!("permute {} ship {} bit {}", orientation, col / 2, row),
                                &mut region,
                                self.config.permuted_bits[col],
                                row,
                            )?;
                        }
                    }
                    // assign transposed commitment
                    let mut assigned = Vec::<AssignedCell<F, F>>::new();
                    for row in 0..BOARD_SIZE {
                        assigned.push(region.assign_advice(
                            || format!("assign tranposed bit {}", row),
                            self.config.transposed_bits,
                            row,
                            || Value::known(bits[row].clone()),
                        )?);
                        // toggle transposed row constraint
                        self.config.selector.enable(&mut region, row)?;
                    }
                    Ok(assigned.try_into().unwrap())
                },
            )
            .unwrap())
    }
}
