use {
    halo2_gadgets::poseidon::{primitives::*, Hash, Pow5Chip, Pow5Config},
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
    },
    std::marker::PhantomData,
};

#[derive(Debug, Clone)]
struct PoseidonConfig<
    F: FieldExt,
    const L: usize,
> {
    pub trace: Column<Advice>,
    pub state: [Column<Advice>; 3],
    pub partial_sbox: Column<Advice>,
    pub rc_a: [Column<Fixed>; 3],
    pub rc_b: [Column<Fixed>; 3],
    pub instance: Column<Instance>,
    pub pow5: Pow5Config<F, 3, 2>,
}

#[derive(Debug, Clone)]
struct PoseidonCircuit<
    S: Spec<F, 3, 2>,
    F: FieldExt,
    const L: usize,
> {
    message: [Value<F>; L],
    output: Value<F>,
    _marker: PhantomData<S>,
}

pub trait PoseidonInstructions<
    S: Spec<F, 3, 2>,
    F: FieldExt,
    const L: usize,
>
{
    /**
     * Assign the inputs to the poseidon hash function
     *
     * @return - array of assigned cells storing the plaintext hash inputs
     */
    fn load_plaintext(
        &self,
        layouter: &mut impl Layouter<F>,
        config: PoseidonConfig<F, L>,
    ) -> Result<[AssignedCell<F, F>; L], Error>;

    /**
     * Compute the poseidon hash of a given array of inputs
     *
     * @param assigned - assigned cells pointing to plaintext inputs to hash function
     * @return - assigned cell storing the output of the poseidon hash
     */
    fn hash(
        &self,
        layouter: &mut impl Layouter<F>,
        config: PoseidonConfig<F, L>,
        assigned: [AssignedCell<F, F>; L],
    ) -> Result<AssignedCell<F, F>, Error>;

    /**
     * Expose the output of the poseidon hash function to an instance column
     *
     * @param value - the assigned cell storing the hash function output to expose publicly
     * @param row - the instance column row offset to assign to
     * @return - ok if synthesis executes successfully
     */
    fn expose_public(
        &self,
        layouter: &mut impl Layouter<F>,
        config: PoseidonConfig<F, L>,
        value: AssignedCell<F, F>,
        row: usize
    ) -> Result<(), Error>;
}

impl<
        S: Spec<F, 3, 2>,
        F: FieldExt,
        const L: usize,
    > Circuit<F> for PoseidonCircuit<S, F, L>
{
    type Config = PoseidonConfig<F, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: (0..L)
                .map(|i| Value::unknown())
                .collect::<Vec<Value<F>>>()
                .try_into()
                .unwrap(),
            output: Value::unknown(),
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonConfig<F, L> {
        let trace = meta.advice_column();
        meta.enable_equality(trace);
        let state: [Column<Advice>; 3] = (0..3)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let partial_sbox = meta.advice_column(); 
        let rc_a: [Column<Fixed>; 3] = (0..3)
            .map(|_| meta.fixed_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let rc_b: [Column<Fixed>; 3] = (0..3)
            .map(|_| meta.fixed_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        for i in 0..3 {
            meta.enable_equality(state[i]);
            // meta.enable_equality(rc_a[0]);
            // meta.enable_equality(rc_b[0]);
        }
        meta.enable_constant(rc_b[0]);

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let pow5 =
            Pow5Chip::<F, 3, 2>::configure::<S>(meta, state, partial_sbox, rc_a, rc_b);

        Self::Config {
            trace,
            state,
            partial_sbox,
            rc_a,
            rc_b,
            instance,
            pow5
        }
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<F, L>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let plaintext = self.load_plaintext(&mut layouter, config.clone())?;
        let ciphertext = self.hash(&mut layouter, config.clone(), plaintext)?;
        self.expose_public(&mut layouter, config, ciphertext, 0)
    }
}

impl<
        S: Spec<F, 3, 2>,
        F: FieldExt,
        const L: usize,
    > PoseidonInstructions<S, F, L> for PoseidonCircuit<S, F, L>
{
    fn load_plaintext(
        &self,
        layouter: &mut impl Layouter<F>,
        config: PoseidonConfig<F, L>,
    ) -> Result<[AssignedCell<F, F>; L], Error> {
        Ok(layouter.assign_region(
            || "load plaintext",
            |mut region| -> Result<[AssignedCell<F, F>; L], Error> {
                let mut assigned = Vec::<AssignedCell<F, F>>::new();
                for i in 0..self.message.len() {
                    assigned.push(region.assign_advice(
                        || format!("plaintext word {}", i + 1),
                        config.trace,
                        i,
                        || self.message[i].to_owned(),
                    )?);
                }
                Ok(assigned.try_into().unwrap())
            },
        )?)
    }

    fn hash(
        &self,
        layouter: &mut impl Layouter<F>,
        config: PoseidonConfig<F, L>,
        assigned: [AssignedCell<F, F>; L],
    ) -> Result<AssignedCell<F, F>, Error> {
        let chip = Pow5Chip::<F, 3, 2>::construct(config.pow5);
        let hasher = Hash::<_, _, S, ConstantLength<L>, 3, 2>::init(
            chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), assigned)
    }

    fn expose_public(
        &self,
        layouter: &mut impl Layouter<F>,
        config: PoseidonConfig<F, L>,
        value: AssignedCell<F, F>,
        row: usize
    ) -> Result<(), Error> {
        layouter.constrain_instance(value.cell(), config.instance, row)
    }
}

mod tests {
    use std::marker::PhantomData;

    use super::PoseidonCircuit;
    use halo2_gadgets::poseidon::{
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    };
    use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};

    #[test]
    fn test() {
        let input = 99u64;
        let message = [Fp::from(input), Fp::from(input)];
        let output =
            poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);

        let circuit = PoseidonCircuit::<OrchardNullifier, Fp, 2> {
            message: message.map(|x| Value::known(x)),
            output: Value::known(output),
            _marker: PhantomData,
        };
        println!("output: {:?}", output);
        let public_input = vec![output];
        let prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();
        prover.assert_satisfied();
    }
}
