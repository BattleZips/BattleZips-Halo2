// use crate::board::board_table::BoardTable;
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;
use crate::board::utils::SHIP_LENGTHS;

#[derive(Debug, Clone)]
pub(super) struct BoardConfig<F> {
    pub ship_length: Column<Fixed>,
    pub x: Column<Advice>,
    pub y: Column<Advice>,
    pub z: Column<Advice>,
    pub q_range: Selector,
    pub _marker: PhantomData<F>,
}

impl<F: FieldExt> BoardConfig<F> {
    /**
     * TBH IDK WHAT EXACTLY CONFIGURE IS COMPARED TO SYNTH
     */
    pub(super) fn configure(meta: &mut ConstraintSystem<F>, config: BoardConfig<F>) -> Self {
        // Ship input range check gate
        meta.create_gate("ship range check", |meta| {
            // witness state
            let q_range = meta.query_selector(config.q_range);
            let ship_length = meta.query_fixed(config.ship_length, Rotation::cur());
            let x = meta.query_advice(config.x, Rotation::cur());
            let y = meta.query_advice(config.y, Rotation::cur());
            let z = meta.query_advice(config.z, Rotation::cur());

            // define binary check (z ∈ [0, 1])
            let binary_check = |val: Expression<F>| {
                val.clone() * (val.clone() - Expression::Constant(F::one()))
            };

            // define ship range check (x, y ∈ [0, 9])
            let decimal_check = |val: Expression<F>| {
                (0..=9).fold(val.clone(), |expression, i| {
                    expression * (Expression::Constant(F::from(i as u64)) - val.clone())
                })
            };

            // define ship length extension check
            let length_check =
                |x: Expression<F>, y: Expression<F>, z: Expression<F>, length: Expression<F>| {
                    let one = Expression::Constant(F::one());
                    // get range of extension for X if Z = 0 and Y if Z = 1 given ship length
                    let x_extension = (one.clone() - z.clone()) * (x.clone() + length.clone() - one.clone());
                    let y_extension = z.clone() * (y.clone() - length.clone() + one.clone());
                    let value = x_extension + y_extension;
                    decimal_check(value)
                };

            /// let value = Expression::Constant(F::from(10))
            // * (x.clone() + ship_length.clone() * (Expression::Constant(F::one()) - ship[2].clone()))
            // + ship[1].clone()
            // + ship_length.clone() * ship[2].clone();
            Constraints::with_selector(
                q_range,
                [
                    ("x decimal range check", decimal_check(x.clone())),
                    ("y decimal range check", decimal_check(y.clone())),
                    ("z binary range check", binary_check(z.clone())),
                    ("ship length range check", length_check(x.clone(), y.clone(), z.clone(), ship_length.clone()))
                ],
            )
        });

        // // Board coordinate lookup gate
        // //
        // meta.lookup(|meta| {
        //     let q_lookup = meta.query_selector(q_lookup);
        //     let value = meta.query_advice(value, Rotation::cur());
        //     vec![(q_lookup * value, table.value)]
        // });

        config
    }

    pub(super) fn assign_ships(
        &self,
        mut layouter: impl Layouter<F>,
        ships: [[Value<F>; 3]; 5],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Assign ships to advice cells",
            |mut region| {
                for offset in 0..ships.len() {
                    // enable range and lookup selectors
                    self.q_range.enable(&mut region, offset);

                    // Assign x, y, z, length
                    let ship = ships[offset];
                    region.assign_advice(|| "assign x", self.x, offset, || ship[0]);
                    region.assign_advice(|| "assign y", self.y, offset, || ship[1]);
                    region.assign_advice(|| "assign z", self.z, offset, || ship[2]);
                    region.assign_fixed(
                        || "assign ship_length",
                        self.ship_length,
                        offset,
                        || Value::known(F::from(SHIP_LENGTHS[offset] as u64)),
                    );
                }
                Ok(())
            },
        )
    }
}
