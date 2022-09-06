use crate::board::board_table::BoardTable;
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};

#[derive(Debug, Clone)]
struct BoardConfig<F: FieldExt> {
    length: Column<Fixed>,
    x: Column<Advice>,
    y: Column<Advice>,
    z: Column<Advice>,
    q_range: Selector,
    q_placement: Selector,
    table: BoardTable<F>,
}

impl<F: FieldExt> BoardConfig<F> {
    fn configure(meta: &mut ConstraintSystem<F>, value: Column<Advice>) -> Self {
        // configure public columns
        let length = meta.fixed_column();
        // configure advice columns
        let x = meta.advice_column();
        let y = meta.advice_column();
        let z = meta.advice_column();

        // Toggle ship placement range constraint
        let q_range = meta.selector();
        // Toggle board coordinate lookup
        let q_placement = meta.complex_selector();

        // Configure a lookup table
        let table = BoardTable::configure(meta);

        let config = Self {
            x,
            y,
            z,
            q_range,
            q_placement,
            table: table.clone(),
        };

        // Ship input range check gate
        meta.create_gate("ship range check", |meta| {
            // witness state
            let q_range = meta.query_selector(q_range);
            let length = meta.query_fixed(length, Rotation::cur());
            let x = meta.query_advice(x, Rotation::cur());
            let y = meta.query_advice(y, Rotation::cur());
            let z = meta.query_advice(z, Rotation::cur());

            // define binary check (z ∈ [0, 1])
            let binary_check = |z: Expression<F>| z * (z - Expression::Constant(F::from(1u64)));

            // define ship range check (x, y ∈ [0, 9] (plus ship length))
            let range_check = |ship: [Expression<F>; 3], length: Expression<F>| {
                let value = Expression::Constant(F::from(10))
                    * (x + length * (Expression::Constant(F::one()) - ship[2]))
                    + ship[1]
                    + length * ship[2];
                (0..=9).fold(value.clone(), |expression, i| {
                    expression * (Expression::Constant(F::from(i as u64)) - value.clone())
                })
            };
            Constraints::with_selector(q_range, [
                ("z range check", binary_check(z)),
                ("x/y range check", range_check([x, y, z], length))
            ])
        });

        // Board coordinate lookup gate
        //
        meta.lookup(|meta| {
            let q_lookup = meta.query_selector(q_lookup);
            let value = meta.query_advice(value, Rotation::cur());
            vec![(q_lookup * value, table.value)]
        });

        config
    }

    fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<Assigned<F>>,
        range: usize,
    ) -> Result<(), Error> {
        assert!(range <= LOOKUP_RANGE);
        if range < RANGE {
            layouter.assign_region(
                || "Assign value",
                |mut region| {
                    let offset = 0;
                    // Enable q_range_check
                    self.q_range_check.enable(&mut region, offset);

                    // Assign given value
                    region.assign_advice(|| "assign value", self.value, offset, || value)?;
                    Ok(())
                },
            )
        } else {
            layouter.assign_region(
                || "Assign value for lookup range check",
                |mut region| {
                    let offset = 0;
                    // Enable q_lookup
                    self.q_lookup.enable(&mut region, offset);

                    // Assign given value
                    region.assign_advice(|| "assign value", self.value, offset, || value)?;
                    Ok(())
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        halo2_proofs::{
            circuit::floor_planner::V1,
            dev::{FailureLocation, MockProver, VerifyFailure},
            pasta::Fp,
            plonk::{Any, Circuit},
        },
    };

    #[derive(Default)]
    struct MyCircuit<F: FieldExt, const RANGE: usize, const LOOKUP_RANGE: usize> {
        value: Value<Assigned<F>>,
        large_value: Value<Assigned<F>>,
    }

    impl<F: FieldExt, const RANGE: usize, const LOOKUP_RANGE: usize> Circuit<F>
        for MyCircuit<F, RANGE, LOOKUP_RANGE>
    {
        type Config = RangeCheckConfig<F, RANGE, LOOKUP_RANGE>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let value = meta.advice_column();
            RangeCheckConfig::configure(meta, value)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.table.load(&mut layouter)?;
            config.assign(layouter.namespace(|| "Assign value"), self.value, RANGE)?;
            config.assign(
                layouter.namespace(|| "Assign large value"),
                self.value,
                LOOKUP_RANGE,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_range_check() {
        let k = 9;
        const RANGE: usize = 8;
        const LOOKUP_RANGE: usize = 256;

        // Successful cases
        for i in 0..RANGE {
            let circuit = MyCircuit::<Fp, RANGE, LOOKUP_RANGE> {
                value: Value::known(Fp::from(i as u64).into()),
                large_value: Value::known(Fp::from(i as u64).into()),
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            prover.assert_satisfied();
        }

        // // Unsuccessful case v = 8
        // let circuit = MyCircuit::<Fp, RANGE> {
        //     value: Value::known(Fp::from(RANGE as u64).into()),
        // };
        // let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        // assert_eq!(
        //     prover.verify(),
        //     Err(vec![VerifyFailure::ConstraintNotSatisfied {
        //         constraint: ((0, "Range check").into(), 0, "range check").into(),
        //         location: FailureLocation::InRegion {
        //             region: (0, "Assign value").into(),
        //             offset: 0
        //         },
        //         cell_values: vec![(((Any::Advice, 0).into(), 0).into(), "0x8".to_string())]
        //     }])
        // )
    }
}
