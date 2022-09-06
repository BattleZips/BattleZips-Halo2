use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

/// Helper to check value witnessed in a given cell is withen a set range
/// Dependig on range, helper uses either a range-check expression (small ranges)
/// or a lookup (large ranges)
///
///        value    |       q_range_check   |    q_lookup   |       table_value    |
/// --------------------------------------------------------------------------------
///         v       |          1            |       0       |           0          |
///         v`      |          0            |       1       |           1          |

#[derive(Debug, Clone)]
struct RangeCheckConfig<F: FieldExt, const RANGE: usize, const LOOKUP_RANGE: usize> {
    value: Column<Advice>,
    q_range_check: Selector,
    q_lookup: Selector,
    table: RangeCheckTable<F, LOOKUP_RANGE>,
}

mod table;
use table::RangeCheckTable;

impl<F: FieldExt, const RANGE: usize, const LOOKUP_RANGE: usize>
    RangeCheckConfig<F, RANGE, LOOKUP_RANGE>
{
    fn configure(meta: &mut ConstraintSystem<F>, value: Column<Advice>) -> Self {
        // Toggle range check constraint
        let q_range_check = meta.selector();

        // Toggle lookup argument
        let q_lookup = meta.complex_selector();

        // Configure a lookup table
        let table = RangeCheckTable::configure(meta);

        let config = Self {
            q_range_check,
            q_lookup,
            value,
            table: table.clone(),
        };

        // Range-check expression gate
        // For a value `v` and a range `R`, check that `v < R`
        meta.create_gate("Range check", |meta| {
            let q_range_check = meta.query_selector(q_range_check);
            let value = meta.query_advice(value, Rotation::cur());
            let range_check = |range: usize, value: Expression<F>| {
                (0..range).fold(value.clone(), |expression, i| {
                    expression * (Expression::Constant(F::from(i as u64)) - value.clone())
                })
            };
            Constraints::with_selector(q_range_check, [("range check", range_check(RANGE, value))])
        });

        // Range-check lookup gate
        // Check that value v is contained within a lookup table of values 0..RANGE
        meta.lookup(|meta| {
            let q_lookup = meta.query_selector(q_lookup);
            println!("Q_LOOKUP: {:?}", q_lookup);
            let value = meta.query_advice(value, Rotation::cur());
            println!("VALUE: {:?}", q_lookup);
            println!("TABLE VALUE: {:?}", table.value);
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
        large_value: Value<Assigned<F>>
    }

    impl<F: FieldExt, const RANGE: usize, const LOOKUP_RANGE: usize> Circuit<F> for MyCircuit<F, RANGE, LOOKUP_RANGE> {
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
            config.assign(layouter.namespace(|| "Assign large value"), self.value, LOOKUP_RANGE)?;
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
                large_value: Value::known(Fp::from(i as u64).into())
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
