#[cfg(test)]
mod test {
    use std::fmt::Binary;

    use {
        crate::{
            bits2num::bits2num::{Bits2NumChip, Bits2NumConfig},
            placement::{
                chip::{PlacementChip, PlacementConfig},
                gadget::{PlacementGadget, CHIP_SIZE},
            },
            utils::{
                ship::{Ship, ShipType},
                binary::BinaryValue
            }
        },
        halo2_proofs::{
            arithmetic::FieldExt,
            circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
            dev::{CircuitLayout, FailureLocation, MockProver, VerifyFailure},
            pasta::Fp,
            plonk::{Advice, Any, Circuit, Column, ConstraintSystem, Error},
        },
    };

    #[derive(Debug, Clone, Copy)]
    struct TestConfig<const S: usize> {
        pub placement_config: PlacementConfig<Fp, S>,
        pub bits2num_config: [Bits2NumConfig; 2],
        pub trace: Column<Advice>,
    }

    #[derive(Debug, Clone, Copy)]
    struct TestCircuit<const S: usize> {
        pub values: [BinaryValue; 2],
        pub gadget: PlacementGadget<Fp>,
    }

    impl<const S: usize> TestCircuit<S> {
        fn new(x: BinaryValue, y: BinaryValue) -> TestCircuit<S> {
            let gadget = PlacementGadget::<Fp>::new(ship);
            TestCircuit { gadget }
        }

        /**
         * Assign the horizontal and vertical placement values in the test circuit
         * @dev either H or V will be set to 0
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
                    let commitment = self.gadget.ship.bits().lower_u128();
                    let horizontal = if self.gadget.ship.z {
                        Value::known(Fp::zero())
                    } else {
                        Value::known(Fp::from_u128(commitment))
                    };
                    let vertical = if self.gadget.ship.z {
                        Value::known(Fp::from_u128(commitment))
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
            let chip = PlacementChip::<Fp, S>::new(config.placement_config);
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

    #[test]
    fn invalid_placement_0() {
        // check that a ship vertically placed on multiple rows fails
        // ex: [49, 50, 51, 52]
        const SHIP_LENGTH: usize = 5;
        let ship = ShipPlacement::<SHIP_LENGTH>::construct(4, 8, true);
        let circuit = TestCircuit::<SHIP_LENGTH>::new(ship);
        let prover = MockProver::run(CHIP_SIZE, &circuit, vec![]).unwrap();
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (5, "running sum constraints").into(),
                    1,
                    "One full bit window"
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (4, "constrain running sum output").into(),
                    offset: 0
                },
                cell_values: vec![(((Any::Advice, 2).into(), 0).into(), String::from("0"))]
            }])
        );
    }

    #[test]
    fn invalid_placement_1() {
        // check that a ship horizontally placed on multiple rows fails
        // ex: [39, 40]
        const SHIP_LENGTH: usize = 2;
        let ship = ShipPlacement::<SHIP_LENGTH>::construct(9, 3, false);
        let circuit = TestCircuit::<SHIP_LENGTH>::new(ship);
        let prover = MockProver::run(CHIP_SIZE, &circuit, vec![]).unwrap();
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (5, "running sum constraints").into(),
                    1,
                    "One full bit window"
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (4, "constrain running sum output").into(),
                    offset: 0
                },
                cell_values: vec![(((Any::Advice, 2).into(), 0).into(), String::from("0"))]
            }])
        );
    }

    #[test]
    fn invalid_placement_2() {
        // check that an attempt to assign both H and V fails
        // const SHIP_LENGTH: usize = 4;
        // let ship = ShipPlacement::<SHIP_LENGTH>::construct(9, 3, false);
        // let circuit = TestCircuit::<SHIP_LENGTH>::new(ship);
        // let prover = MockProver::run(CHIP_SIZE, &circuit, vec![]).unwrap();
        // assert_eq!(
        //     prover.verify(),
    }

    #[test]
    fn invalid_placement_3() {
        // check that a placement with not enough bits set fails
        // fails both bit_sum and full_window_sum
        // check that a valid placement of battleship vertically at 5, 2 succeeds
    }

    #[test]
    fn invalid_placement_4() {
        // check that a placement with correct # of bits but 1 > full_window_sum fails
    }

    #[test]
    fn invalid_placement_5() {
        // check that a placement with too many bits but 1 = full_window_sum fails
    }

    #[test]
    fn invalid_placement_6() {
        // check that a placement with too many bits and 1 < full_window_sum fails
    }

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
