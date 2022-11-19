use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

/// Configuration elements for the circuit defined here.
/// @TODO figure out how tf this works
#[derive(Debug, Clone, Copy)]
pub struct Bits2NumConfig {
    /// Configures a column for the bits.
    pub bits: Column<Advice>,
    /// Configures a column for the lc1.
    lc1: Column<Advice>,
    /// Configures a column for the e2.
    e2: Column<Advice>,
    /// Configures a fixed boolean value for each row of the circuit.
    selector: Selector,
}

/// Constructs a cell and a variable for the circuit.
#[derive(Clone)]
pub struct Bits2NumChip<F: FieldExt, const B: usize> {
    /// Assigns a cell for the value.
    value: AssignedCell<F, F>,
    /// Constructs bits variable for the circuit.
    bits: [Value<F>; B],
}

impl<F: FieldExt, const B: usize> Bits2NumChip<F, B> {
    /// Create a new chip.
    pub fn new(value: AssignedCell<F, F>, bits: [F; B]) -> Self {
        Self {
            value,
            bits: bits.map(|b| Value::known(b)),
        }
    }

    /// Make the circuit config.
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Bits2NumConfig {
        let bits = meta.advice_column();
        let lc1 = meta.advice_column();
        let e2 = meta.advice_column();
        let fixed = meta.fixed_column();
        let s = meta.selector();

        meta.enable_equality(bits);
        meta.enable_equality(lc1);
        meta.enable_equality(e2);
        meta.enable_constant(fixed);

        meta.create_gate("bits2num", |v_cells| {
            let one_exp = Expression::Constant(F::one());
            let bit_exp = v_cells.query_advice(bits, Rotation::cur());

            let e2_exp = v_cells.query_advice(e2, Rotation::cur());
            let e2_next_exp = v_cells.query_advice(e2, Rotation::next());

            let lc1_exp = v_cells.query_advice(lc1, Rotation::cur());
            let lc1_next_exp = v_cells.query_advice(lc1, Rotation::next());

            let s_exp = v_cells.query_selector(s);

            vec![
                // bit * (1 - bit) == 0
                // Constraining bit to be a boolean.
                s_exp.clone() * (bit_exp.clone() * (one_exp - bit_exp.clone())),
                // e2 + e2 == e2_next
                // Starting from 1, doubling.
                s_exp.clone() * ((e2_exp.clone() + e2_exp.clone()) - e2_next_exp),
                // lc1 + bit * e2 == lc1_next
                // If the bit is equal to 1, e2 will be added to the sum.
                // Example:
                // bit = 1
                // e2 = 1 (first rotation)
                // lc1 = 0
                // If the bit == 1, double the e2.
                // This will be used in the next rotation, if bit == 1 again. (e2_next = 1 + 1 = 2)
                //
                // Check the constraint => (1 * 1 + 0)
                // lc1_next = 1
                s_exp * ((bit_exp * e2_exp + lc1_exp) - lc1_next_exp),
            ]
        });

        Bits2NumConfig {
            bits,
            lc1,
            e2,
            selector: s,
        }
    }

    /// Synthesize the circuit.
    pub fn synthesize(
        &self,
        config: Bits2NumConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<[AssignedCell<F, F>; B], Error> {
        layouter.assign_region(
            || "bits2num",
            |mut region: Region<'_, F>| {
                let mut lc1 =
                    region.assign_advice_from_constant(|| "lc1_0", config.lc1, 0, F::zero())?;
                let mut e2 =
                    region.assign_advice_from_constant(|| "e2_0", config.e2, 0, F::one())?;

                let mut bits: [Option<AssignedCell<F, F>>; B] = [(); B].map(|_| None);
                for i in 0..self.bits.len() {
                    config.selector.enable(&mut region, i)?;

                    let bit = region.assign_advice(|| "bits", config.bits, i, || self.bits[i])?;
                    bits[i] = Some(bit.clone());

                    let next_lc1 =
                        lc1.value().cloned() + bit.value().cloned() * e2.value().cloned();
                    let next_e2 = e2.value().cloned() + e2.value();

                    lc1 = region.assign_advice(|| "lc1", config.lc1, i + 1, || next_lc1)?;
                    e2 = region.assign_advice(|| "e2", config.e2, i + 1, || next_e2)?;
                }

                region.constrain_equal(self.value.cell(), lc1.cell())?;

                Ok(bits.map(|b| b.unwrap()))
            },
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::{metadata, CircuitLayout, FailureLocation, MockProver, VerifyFailure},
        pasta::{group::ff::PrimeFieldBits, Fp},
        plonk::{Any, Circuit},
    };

    use crate::utils::{
        binary::{bits_to_field_elements, bytes2bits, unwrap_bitarr, unwrap_bitvec},
        ship::ShipPlacement,
    };

    #[derive(Clone)]
    struct TestConfig {
        bits2num: Bits2NumConfig,
        trace: Column<Advice>,
    }

    #[derive(Debug, Clone)]
    struct TestCircuit<const B: usize> {
        decimal: Fp,
        binary: [bool; B],
    }

    impl<const B: usize> TestCircuit<B> {
        fn new(x: Fp, y: [bool; B]) -> Self {
            Self {
                decimal: x,
                binary: y,
            }
        }
    }

    impl<const B: usize> Circuit<Fp> for TestCircuit<B> {
        type Config = TestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> TestConfig {
            let bits2num = Bits2NumChip::<_, 256>::configure(meta);
            let trace = meta.advice_column();

            meta.enable_equality(trace);

            TestConfig { bits2num, trace }
        }

        fn synthesize(
            &self,
            config: TestConfig,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let decimal = layouter.assign_region(
                || "trace",
                |mut region: Region<'_, Fp>| {
                    region.assign_advice(
                        || "decimal",
                        config.trace,
                        0,
                        || Value::known(self.decimal),
                    )
                },
            )?;
            let bits = bits_to_field_elements(self.binary);

            let bits2num = Bits2NumChip::new(decimal, bits);
            let _ = bits2num.synthesize(config.bits2num, layouter.namespace(|| "bits2num"))?;

            Ok(())
        }
    }

    #[test]
    fn test_bits_to_num() {
        // Testing field element 0x01234567890abcdef.
        let value = Fp::from(1311768467294899695u64);
        let bits = unwrap_bitarr::<256>(value.to_le_bits());
        let circuit = TestCircuit::<256>::new(value, bits);
        let k = 9;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();

        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_bits_to_num_big() {
        // Testing biggest value in the field.
        let value = Fp::zero().sub(&Fp::one());
        let bits = unwrap_bitarr::<256>(value.to_le_bits());
        let circuit = TestCircuit::<256>::new(value, bits);
        let k = 9;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();

        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_bits_to_num_big_plus() {
        // Testing biggest value in the field + 1.
        // https://neuromancer.sk/std/other/Pallas - value that should wrap around to 0 on Fp
        let mut big_value: [u8; 32] =
            hex::decode("40000000000000000000000000000000224698fc094cf91b992d30ed00000001")
                .unwrap()
                .try_into()
                .unwrap();
        big_value.reverse();
        let bits = bytes2bits::<256>(big_value);
        let circuit = TestCircuit::<256>::new(Fp::zero(), bits);
        let k = 9;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();

        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_bits_to_num_zero_bits() {
        // Testing zero as value with 0 bits.
        let circuit = TestCircuit::<0>::new(Fp::zero(), [false; 0]);
        let k = 9;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();

        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_bits_to_num_zero_value() {
        // Testing zero as value with 254 bits.
        let circuit = TestCircuit::<254>::new(Fp::zero(), [false; 254]);
        let k = 9;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();

        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_battlezips() {
        // demonstration that ShipPlacement gadget interfaces as intended with bits2num circuit
        // demonstrate with a carrier ship (length 5) placed vertically at x:4, y: 3

        // prepare values to be witnessed by mock circuit
        const SHIP_LENGTH: usize = 5;
        const BOARD_SIZE: usize = 100;
        let ship = ShipPlacement::<SHIP_LENGTH>::construct(4, 3, true);
        let bits = unwrap_bitvec(ship.to_bits());
        let decimal = ship.to_decimal();

        // use values with bits2num test circuit
        let circuit = TestCircuit::<BOARD_SIZE>::new(Fp::from_u128(decimal), bits);
        let k = 9;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        
        // check that value fails if decimal is incremented
        let decimal = ship.to_decimal() + 1u128;
        let circuit = TestCircuit::<BOARD_SIZE>::new(Fp::from_u128(decimal), bits);
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::Permutation {
                column: metadata::Column::from((Any::Advice, 1)),
                location: FailureLocation::InRegion {
                    region: (1, "bits2num").into(),
                    offset: 100
                }
            }, VerifyFailure::Permutation {
                column: metadata::Column::from((Any::Advice, 3)),
                location: FailureLocation::InRegion {
                    region: (0, "trace").into(),
                    offset: 0
                }
            }
            ])
        );
    }

    #[test]
    fn print_layout() {
        use plotters::prelude::*;
        let circuit = TestCircuit::<256>::new(Fp::one(), [false; 256]);
        let root =
            BitMapBackend::new("src/bits2num/bits2num_layout.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Bits2Num Circuit Layout", ("sans-serif", 60))
            .unwrap();

        CircuitLayout::default()
            // You can optionally render only a section of the circuit.
            .view_width(0..2)
            .view_height(0..16)
            // You can hide labels, which can be useful with smaller areas.
            .show_labels(false)
            // Render the circuit onto your area!
            // The first argument is the size parameter for the circuit.
            .render(8, &circuit, &root)
            .unwrap();
    }

    // // #[test]
    // // fn test_bits_to_num_production() {
    // // 	let numba = Fr::from(1311768467294899695u64);
    // // 	let numba_bytes = [
    // // 		239, 205, 171, 144, 120, 86, 52, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // // 		0, 0, 0, 0, 0, 0, 0,
    // // 	];

    // // 	let circuit = TestCircuit::<256>::new(numba, numba_bytes);
    // // 	let k = 9;
    // // 	let rng = &mut rand::thread_rng();
    // // 	let params = generate_params(k);
    // // 	let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[], rng).unwrap();

    // // 	assert!(res);
    // // }
}
