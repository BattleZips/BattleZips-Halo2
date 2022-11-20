#[cfg(test)]
mod test {
    use {
        crate::{
            placement::{
                chip::{PlacementChip, PlacementConfig},
                gadget::{PlacementGadget, CHIP_SIZE},
            },
            utils::ship::ShipPlacement,
        },
        halo2_proofs::{
            arithmetic::FieldExt,
            circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
            dev::{CircuitLayout, MockProver},
            pasta::Fp,
            plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
        },
    };

    #[derive(Debug, Clone, Copy)]
    struct TestConfig<const S: usize> {
        pub placement_config: PlacementConfig<Fp, S>,
        pub trace: Column<Advice>,
    }

    #[derive(Debug, Clone, Copy)]
    struct TestCircuit<const S: usize> {
        pub ship: ShipPlacement<S>,
        pub gadget: PlacementGadget<Fp, S>,
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
            _ = chip.synthesize(
                layouter,
                commitments[0].clone(),
                commitments[1].clone(),
                self.gadget,
            );
            Ok(())
        }
    }

    #[test]
    fn valid_placement_0() {
        // check that a valid placement of carrier horizontally at 0, 0 succeeds
        const SHIP_LENGTH: usize = 5;
        let ship = ShipPlacement::<SHIP_LENGTH>::construct(0, 0, false);
        let circuit = TestCircuit::<SHIP_LENGTH>::new(ship);
        let prover = MockProver::run(CHIP_SIZE, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn valid_placement_1() {
        // check that a valid placement of battleship vertically at 5, 2 succeeds
        const SHIP_LENGTH: usize = 4;
        let ship = ShipPlacement::<SHIP_LENGTH>::construct(5, 2, true);
        let circuit = TestCircuit::<SHIP_LENGTH>::new(ship);
        let prover = MockProver::run(CHIP_SIZE, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // fn invalid_placement_0() {
    //     // check that a ship horizontally placed on multiple rows fails
    //     // ex: [49, 50, 51, 52]
    //     const SHIP_LENGTH: usize = 5;
    //     let ship = ShipPlacement::<SHIP_LENGTH>::construct(5, 2, true);
    //     let circuit = TestCircuit::<SHIP_LENGTH>::new(ship);
    //     let prover = MockProver::run(CHIP_SIZE, &circuit, vec![]).unwrap();
    //     assert_eq!(prover.verify(), Ok(()));
    // }

    // fn invalid_placement_1() {
    //     // check that a ship vertically placed on multiple rows fails
    // }

    // fn invalid_placement_2() {

    // }

    #[test]
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
            .render(CHIP_SIZE, &circuit, &root)
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
