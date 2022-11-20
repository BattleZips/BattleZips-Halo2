#[cfg(test)]
mod test {
    use halo2_proofs::arithmetic::Field;


    use {
        halo2_proofs::{
            arithmetic::{FieldExt, lagrange_interpolate},
            circuit::{Layouter, AssignedCell, Value, SimpleFloorPlanner},
            dev::{CircuitLayout, MockProver},
            pasta:: Fp,
            plonk::{Circuit, Column, Advice, Error, ConstraintSystem}
        },
        crate::{
            placement::{
                chip::{PlacementChip, PlacementConfig},
                gadget::{PlacementGadget}
            },
            utils::ship::ShipPlacement
        }
    };

    #[derive(Debug, Clone, Copy)]
    struct TestConfig<const S: usize> {
        pub placement_config: PlacementConfig<Fp, S>,
        pub trace: Column<Advice>,
    }

    #[derive(Debug, Clone, Copy)]
    struct TestCircuit<const S: usize> {
        pub ship: ShipPlacement<S>,
        pub gadget: PlacementGadget<Fp, S>
    }

    impl<const S: usize> TestCircuit<S> {
        fn new(ship: ShipPlacement<S>) -> TestCircuit<S> {
            let gadget = PlacementGadget::<Fp, S>::new(ship);
            TestCircuit { ship, gadget }
        }

        /**
         * Assign the horizontal and vertical placement values in the test circuit
         *
         * @return - if successful, references to cell assignments for [horizontal, vertical]
         */
        fn witness_trace(
            &self,
            layouter: &mut impl Layouter<Fp>,
            config: TestConfig<S>,
        ) -> Result<[AssignedCell<Fp, Fp>; 2], Error> {
            Ok(layouter.assign_region(
                || "placement ship test trace",
                |mut region| {
                    // compute horizontal and vertical values
                    let decimal = self.ship.to_decimal();
                    let horizontal = if self.ship.z {
                        Value::known(Fp::zero())
                    } else {
                        Value::known(Fp::from_u128(decimal))
                    };
                    let vertical = if self.ship.z {
                        Value::known(Fp::from_u128(decimal))
                    } else {
                        Value::known(Fp::zero())
                    };
                    let horizontal_cell = region.assign_advice(
                        || "assign horizontal to test trace",
                        config.trace,
                        0,
                        || horizontal,
                    )?;
                    let vertical_cell = region.assign_advice(
                        || "assign vertical to test trace",
                        config.trace,
                        1,
                        || vertical,
                    )?;
                    Ok([horizontal_cell, vertical_cell])
                },
            )?)
        }
    }

    impl<const S: usize> Circuit<Fp> for TestCircuit<S> {
        type Config = TestConfig<S>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> TestConfig<S> {
            let placement_config = PlacementChip::<Fp, S>::configure(meta);
            let trace = meta.advice_column();
            meta.enable_equality(trace);

            TestConfig {
                placement_config,
                trace,
            }
        }

        fn synthesize(
            &self,
            config: TestConfig<S>,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            // assign test trace
            let commitments = self.witness_trace(&mut layouter, config)?;
            let chip = PlacementChip::<Fp, S>::new(config.placement_config, self.ship);
            _ = chip.synthesize(layouter, commitments[0].clone(), commitments[1].clone(), self.gadget);
            Ok(())
        }
    }

    #[test]
    fn placement_valid_case_0() {
        // check that a valid placement of carrier horizontally at 0, 0 succeeds
        const SHIP_LENGTH: usize = 5;
        let ship = ShipPlacement::<SHIP_LENGTH>::construct(0, 0, false);
        let circuit = TestCircuit::<SHIP_LENGTH>::new(ship);
        let k = 8;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // #[test]
    // fn inverse_test() {
    //     let ship_len = Fp::from(5);
    //     let count = Fp::from(4);
    //     let inv = ship_len.invert().unwrap_or(Fp::zero());
    //     ship_len.is_zero();
    //     let exp = count * inv;
    //     println!("inv: {:?}", exp);
    //     let points = [Fp::from(0), Fp::from(1), Fp::from(2), Fp::from(3), Fp::from(4), Fp::from(5)];
    //     let evals = [Fp::from(0), Fp::from(0), Fp::from(0), Fp::from(0), Fp::from(0), Fp::from(1)];
    //     let coeff = lagrange_interpolate(&points, &evals);

    //     // evaluate y for x in the interpolated polynomial
    //     let exp = |x: usize, coeff: &Vec<Fp> | -> Fp {
    //         let x = Fp::from(x as u64);
    //         let mut y = Fp::zero();
    //         for i in 0..coeff.len() {
    //             let x_pow = x.clone().pow_vartime(&[i as u64]);
    //             y = y + coeff[i].clone() * x_pow;
    //         };
    //         y
    //     };

    //     println!("0: {:?}", exp(0, &coeff));
    //     println!("1: {:?}", exp(1, &coeff));
    //     println!("1: {:?}", exp(2, &coeff));
    //     println!("2: {:?}", exp(3, &coeff));
    //     println!("3: {:?}", exp(4, &coeff));
    //     println!("4: {:?}", exp(5, &coeff));
    //     println!("5: {:?}", exp(6, &coeff));


    // }

    // #[test]
    // fn placement_invalid_case_0() {
    //     // check that an invalid placement (attempts to assign less than necessary amount of bits)

    // }

    // #[test]
    fn print_circuit() {
        use plotters::prelude::*;
        const SHIP_LENGTH: usize = 5;
        let ship = ShipPlacement::<SHIP_LENGTH>::construct(0, 0, false);
        let circuit = TestCircuit::<SHIP_LENGTH>::new(ship);
        let root = BitMapBackend::new("src/placement/placement_layout.png", (1024, 768))
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
            .render(9, &circuit, &root)
            .unwrap();
    }
}

// // iterator to try ship of every size on
// // correct placement
// // incorrect:
// //  - nonzero h, v
// //  - spread out bits in commitment (not in order)
// //  - > ship_len bits in commitment
// //  - < ship_len bits in commitment