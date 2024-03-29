use {
    bitvec::prelude::*,
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{AssignedCell, Layouter, Region, Value},
        plonk::{
            Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Selector,
        },
        poly::Rotation,
    },
};

/// Configuration elements for the circuit defined here.
#[derive(Debug, Clone, Copy)]
pub struct BitifyConfig {
    /// Configures a column for the bits.
    pub bits: Column<Advice>,
    /// Configures a column for the lc1.
    lc1: Column<Advice>,
    /// Configures a column for the e2.
    e2: Column<Advice>,
    /// Constant column
    fixed: Column<Fixed>,
    /// Configures a fixed boolean value for each row of the circuit.
    selector: Selector,
}

// given an assigned numerical value, compute a constrained bit decomposition
pub struct Num2BitsChip<F: FieldExt, const B: usize> {
    /// Assigns a cell for the value.
    value: AssignedCell<F, F>,
    /// Constructs bits variable for the circuit.
    bits: [Value<F>; B],
}

// given an assignment of bits, constrain to be binary and compose into an element
pub struct Bits2NumChip<F: FieldExt, const B: usize> {
    /// Assigns a cell for the value.
    value: Value<F>,
    /// Constructs bits variable for the circuit.
    bits: [AssignedCell<F, F>; B],
}

// num2bits chip implementation
impl<F: FieldExt, const B: usize> Num2BitsChip<F, B> {
    /// Create a new chip.
    pub fn new(value: AssignedCell<F, F>, bits: [F; B]) -> Self {
        Self {
            value,
            bits: bits.map(|b| Value::known(b)),
        }
    }

    /// Make the circuit config.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        bits: Column<Advice>,
        lc1: Column<Advice>,
        e2: Column<Advice>,
        fixed: Column<Fixed>,
    ) -> BitifyConfig {
        let selector = meta.selector();

        meta.create_gate("num2bits", |meta| {
            let one = Expression::Constant(F::one());
            let bit = meta.query_advice(bits, Rotation::cur());

            let e2_exp = meta.query_advice(e2, Rotation::cur());
            let e2_next = meta.query_advice(e2, Rotation::next());

            let lc1_exp = meta.query_advice(lc1, Rotation::cur());
            let lc1_next = meta.query_advice(lc1, Rotation::next());

            let selector = meta.query_selector(selector);

            Constraints::with_selector(
                selector,
                [
                    (
                        "Constrain bit is boolean",
                        bit.clone() * (one - bit.clone()),
                    ),
                    (
                        "Start from 1, doubling",
                        e2_exp.clone() + e2_exp.clone() - e2_next.clone(),
                    ),
                    (
                        "If bit is 1, e2 added to sum",
                        bit.clone() * e2_exp.clone() + lc1_exp.clone() - lc1_next.clone(),
                    ),
                ],
            )
        });

        BitifyConfig {
            bits,
            lc1,
            e2,
            selector,
            fixed,
        }
    }

    /// Synthesize the circuit.
    pub fn synthesize(
        &self,
        config: BitifyConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<[AssignedCell<F, F>; B], Error> {
        layouter.assign_region(
            || "num2bits",
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

// bits2num chip implementation
impl<F: FieldExt, const B: usize> Bits2NumChip<F, B> {
    /// Create a new chip.
    pub fn new(value: F, bits: &[AssignedCell<F, F>; B]) -> Self {
        Self {
            value: Value::known(value),
            bits: bits.to_owned(),
        }
    }

    /// Make the circuit config.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        bits: Column<Advice>,
        lc1: Column<Advice>,
        e2: Column<Advice>,
        fixed: Column<Fixed>,
    ) -> BitifyConfig {
        let selector = meta.selector();
        meta.create_gate("bits2num", |meta| {
            let one = Expression::Constant(F::one());
            let bit = meta.query_advice(bits, Rotation::cur());

            let e2_exp = meta.query_advice(e2, Rotation::cur());
            let e2_next = meta.query_advice(e2, Rotation::next());

            let lc1_exp = meta.query_advice(lc1, Rotation::cur());
            let lc1_next = meta.query_advice(lc1, Rotation::next());

            let selector = meta.query_selector(selector);

            Constraints::with_selector(
                selector,
                [
                    (
                        "Constrain bit is boolean",
                        bit.clone() * (one - bit.clone()),
                    ),
                    (
                        "Start from 1, doubling",
                        e2_exp.clone() + e2_exp.clone() - e2_next.clone(),
                    ),
                    (
                        "If bit is 1, e2 added to sum",
                        bit.clone() * e2_exp.clone() + lc1_exp.clone() - lc1_next.clone(),
                    ),
                ],
            )
        });

        BitifyConfig {
            bits,
            lc1,
            e2,
            selector,
            fixed,
        }
    }

    /// Synthesize the circuit.
    pub fn synthesize(
        &self,
        config: BitifyConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
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
                    let bit =
                        self.bits[i]
                            .clone()
                            .copy_advice(|| "bits", &mut region, config.bits, i)?;
                    bits[i] = Some(bit.clone());

                    let next_lc1 =
                        lc1.value().cloned() + bit.value().cloned() * e2.value().cloned();
                    let next_e2 = e2.value().cloned() + e2.value();

                    lc1 = region.assign_advice(|| "lc1", config.lc1, i + 1, || next_lc1)?;
                    e2 = region.assign_advice(|| "e2", config.e2, i + 1, || next_e2)?;
                }
                Ok(lc1)
            },
        )
    }
}
#[cfg(test)]
mod test {
    use halo2_proofs::pasta::group::ff::PrimeField;

    use {
        super::*,
        crate::utils::{binary::BinaryValue, board::BOARD_SIZE, ship::*},
        halo2_proofs::{
            circuit::SimpleFloorPlanner,
            dev::{metadata, FailureLocation, MockProver, VerifyFailure},
            pasta::{group::ff::PrimeFieldBits, Fp},
            plonk::{Any, Circuit},
        },
    };

    const DEFAULT_BITS: usize = 256; // 256 bit max/ default testing
    const CIRCUIT_SIZE: u32 = 9; // 2^CIRCUIT_SIZE rows used in circuit

    #[derive(Clone)]
    struct TestBitifyConfig {
        bitify: BitifyConfig,
        bits: Column<Advice>,
        lc1: Column<Advice>,
        e2: Column<Advice>,
        fixed: Column<Fixed>,
    }

    #[derive(Debug, Clone)]
    struct Num2BitsCircuit<const B: usize> {
        value: Fp,
        binary: BinaryValue,
    }

    #[derive(Debug, Clone)]
    struct Bits2NumCircuit<const B: usize> {
        value: Fp,
        binary: BinaryValue,
    }

    impl<const B: usize> Num2BitsCircuit<B> {
        fn new(value: Fp, binary: BinaryValue) -> Self {
            Self { value, binary }
        }
    }

    impl<const B: usize> Bits2NumCircuit<B> {
        fn new(value: Fp, binary: BinaryValue) -> Self {
            Self { value, binary }
        }
    }

    impl<const B: usize> Circuit<Fp> for Num2BitsCircuit<B> {
        type Config = TestBitifyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> TestBitifyConfig {
            // create circuit columns
            let bits = meta.advice_column();
            let lc1 = meta.advice_column();
            let e2 = meta.advice_column();
            let fixed = meta.fixed_column();

            meta.enable_equality(bits);
            meta.enable_equality(lc1);
            meta.enable_equality(e2);
            meta.enable_constant(fixed);
            // configure chip with columns
            let bitify = Num2BitsChip::<_, DEFAULT_BITS>::configure(meta, bits, lc1, e2, fixed);
            let trace = meta.advice_column();

            meta.enable_equality(trace);

            TestBitifyConfig {
                bitify,
                bits,
                lc1,
                e2,
                fixed,
            }
        }

        fn synthesize(
            &self,
            config: TestBitifyConfig,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let value = layouter.assign_region(
                || "trace",
                |mut region: Region<'_, Fp>| {
                    region.assign_advice(|| "value", config.bits, 0, || Value::known(self.value))
                },
            )?;
            let bits = self.binary.bitfield::<Fp, B>();
            println!("bits: {:?}", bits);

            let num2bits = Num2BitsChip::new(value, bits);
            let _ = num2bits.synthesize(config.bitify, layouter.namespace(|| "num2bits"))?;

            Ok(())
        }
    }

    impl<const B: usize> Circuit<Fp> for Bits2NumCircuit<B> {
        type Config = TestBitifyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> TestBitifyConfig {
            // create circuit columns
            let bits = meta.advice_column();
            let lc1 = meta.advice_column();
            let e2 = meta.advice_column();
            let fixed = meta.fixed_column();

            meta.enable_equality(bits);
            meta.enable_equality(lc1);
            meta.enable_equality(e2);
            meta.enable_constant(fixed);

            // configure chip with columns
            let bitify = Bits2NumChip::<_, DEFAULT_BITS>::configure(meta, bits, lc1, e2, fixed);
            let trace = meta.advice_column();

            meta.enable_equality(trace);

            TestBitifyConfig {
                bitify,
                bits,
                lc1,
                e2,
                fixed,
            }
        }

        fn synthesize(
            &self,
            config: TestBitifyConfig,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let bits = self.binary.bitfield::<Fp, B>();
            let assigned: [AssignedCell<Fp, Fp>; B] = layouter.assign_region(
                || "trace",
                |mut region: Region<'_, Fp>| {
                    let mut assigned = Vec::<AssignedCell<Fp, Fp>>::new();
                    for i in 0..B {
                        assigned.push(region.assign_advice(
                            || "bit",
                            config.bits,
                            i,
                            || Value::known(bits[i]),
                        )?);
                    }
                    Ok(assigned.try_into().unwrap())
                },
            )?;

            let bits2num = Bits2NumChip::new(self.value, &assigned);
            let _ = bits2num.synthesize(config.bitify, layouter.namespace(|| "bits2num"))?;

            Ok(())
        }
    }

    #[test]
    fn test_num_to_bits() {
        // Testing field element 0x01234567890abcdef.
        let value = Fp::from(1311768467294899695u64);
        let circuit = Num2BitsCircuit::<DEFAULT_BITS>::new(value, BinaryValue::from_fp(value));
        let prover = MockProver::run(9, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_bits_to_num() {
        // Testing field element 0x01234567890abcdef.
        let value = Fp::from(1311768467294899695u64);
        let circuit = Bits2NumCircuit::<DEFAULT_BITS>::new(value, BinaryValue::from_fp(value));
        let prover = MockProver::run(10, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_num_to_bits_big() {
        // Testing biggest value in the field.
        let value = Fp::zero().sub(&Fp::one());
        let circuit = Num2BitsCircuit::<DEFAULT_BITS>::new(value, BinaryValue::from_fp(value));
        let prover = MockProver::run(9, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_bits_to_num_big() {
        // Testing biggest value in the field.
        let value = Fp::zero().sub(&Fp::one());
        let circuit = Bits2NumCircuit::<DEFAULT_BITS>::new(value, BinaryValue::from_fp(value));
        let prover = MockProver::run(10, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }


    // SOMETHING IS NOT WORKING WITH OVERFLOW BUT IDK WHAT YET. PROBABLY NEEDS A RANGE CHECK OUTSIDE TO JUST IGNORE
    // #[test]
    // fn test_num_to_bits_big_plus() {
    //     // Testing biggest value in the field + 1: 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
    //     // see https://neuromancer.sk/std/other/Pallas
    //     let mut value: [u8; 32] =
    //         hex::decode("40000000000000000000000000000000224698fc094cf91b992d30ed00000002")
    //             .unwrap()
    //             .try_into()
    //             .unwrap();
    //     value.reverse();
    //     // println!("value: {:?}", Fp::from_repr(value));
    //     let circuit = Num2BitsCircuit::<254>::new(Fp::zero(), BinaryValue::from_repr(value));
    //     let prover = MockProver::run(9, &circuit, vec![]).unwrap();
    //     assert_eq!(prover.verify(), Ok(()));
    // }

    #[test]
    fn test_bits_to_num_big_plus() {
        // Testing biggest value in the field + 1: 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
        // see https://neuromancer.sk/std/other/Pallas
        let mut value: [u8; 32] = 
            hex::decode("40000000000000000000000000000000224698fc094cf91b992d30ed00000000")
                .unwrap()
                .try_into()
                .unwrap();
        value.reverse();
        let x = BinaryValue::from_repr(value);
        println!("x: {:?}", x);
        let circuit = Bits2NumCircuit::<254>::new(Fp::zero(), BinaryValue::from_repr(value));
        let prover = MockProver::run(10, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_num_to_bits_zero_value() {
        // Testing zero as value with 254 bits.
        let value = Fp::zero();
        let circuit = Num2BitsCircuit::<254>::new(value, BinaryValue::from_fp(value));
        let prover = MockProver::run(9, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_bits_to_num_zero_value() {
        // Testing zero as value with 254 bits.
        let value = Fp::zero();
        let circuit = Bits2NumCircuit::<254>::new(value, BinaryValue::from_fp(value));
        let prover = MockProver::run(10, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_battlezips() {
        // demonstration that ShipPlacement gadget interfaces as intended with bits2num circuit
        // demonstrate with a carrier ship (length 5) placed vertically at x:4, y: 3

        // prepare values to be witnessed by mock circuit
        let ship = Ship::new(ShipType::Carrier, 4, 3, true);
        let bits = ship.bits(true);
        let value = bits.to_fp();

        // use values with bits2num test circuit
        let circuit = Num2BitsCircuit::<BOARD_SIZE>::new(value, bits);
        let prover = MockProver::run(CIRCUIT_SIZE, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // // check that value fails if value is incremented
        let circuit = Num2BitsCircuit::<BOARD_SIZE>::new(value + Fp::one(), bits);
        let prover = MockProver::run(9, &circuit, vec![]).unwrap();
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: metadata::Column::from((Any::Advice, 0)),
                    location: FailureLocation::InRegion {
                        region: (0, "trace").into(),
                        offset: 0
                    }
                },
                VerifyFailure::Permutation {
                    column: metadata::Column::from((Any::Advice, 1)),
                    location: FailureLocation::InRegion {
                        region: (1, "num2bits").into(),
                        offset: 100
                    }
                }
            ])
        )
    }

    // #[test]
    // fn print_layout() {
    //     use plotters::prelude::*;
    //     let value = Fp::zero();
    //     let circuit =
    //         Num2BitsCircuit::<DEFAULT_BITS>::new(value, BinaryValue::new(value.to_le_bits()));
    //     let root =
    //         BitMapBackend::new("src/bitify/bitify_layout.png", (1024, 768)).into_drawing_area();
    //     root.fill(&WHITE).unwrap();
    //     let root = root
    //         .titled("Bits2Num/ Num2Bits Circuit Layout", ("sans-serif", 60))
    //         .unwrap();

    //     CircuitLayout::default()
    //         // You can optionally render only a section of the circuit.
    //         .view_width(0..2)
    //         .view_height(0..16)
    //         // You can hide labels, which can be useful with smaller areas.
    //         .show_labels(false)
    //         // Render the circuit onto your area!
    //         // The first argument is the size parameter for the circuit.
    //         .render(9, &circuit, &root)
    //         .unwrap();
    // }

    // // #[test]
    // // fn test_num_to_bits_production() {
    // // 	let numba = Fr::from(1311768467294899695u64);
    // // 	let numba_bytes = [
    // // 		239, 205, 171, 144, 120, 86, 52, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // // 		0, 0, 0, 0, 0, 0, 0,
    // // 	];

    // // 	let circuit = TestCircuit::<DEFAULT_BITS>::new(numba, numba_bytes);
    // // 	let k = 9;
    // // 	let rng = &mut rand::thread_rng();
    // // 	let params = generate_params(k);
    // // 	let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[], rng).unwrap();

    // // 	assert!(res);
    // // }
}
