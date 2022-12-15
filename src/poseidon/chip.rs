use {
    halo2_gadgets::poseidon::{primitives::*, Hash, Pow5Chip, Pow5Config},
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, AssignedCell},
        plonk::{Column, Advice, Fixed, ConstraintSystem, Error},
    },
    std::marker::PhantomData,
};

#[derive(Debug, Clone)]
pub struct PoseidonConfig<F: FieldExt, const WIDTH: usize, const RATE: usize, const L: usize> {
    pub state: [Column<Advice>; WIDTH],
    pub partial_sbox: Column<Advice>,
    pub rc_a: [Column<Fixed>; WIDTH],
    pub rc_b: [Column<Fixed>; WIDTH],
    pub pow5: Pow5Config<F, WIDTH, RATE>
}

#[derive(Debug, Clone)]
pub struct PoseidonChip<
    S: Spec<F, WIDTH, RATE>,
    F: FieldExt,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    config: PoseidonConfig<F, WIDTH, RATE, L>,
    _marker: PhantomData<S>,
}

impl<
        S: Spec<F, WIDTH, RATE>,
        F: FieldExt,
        const WIDTH: usize,
        const RATE: usize,
        const L: usize,
    > PoseidonChip<S, F, WIDTH, RATE, L>
{
    pub fn construct(config: PoseidonConfig<F, WIDTH, RATE, L>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; WIDTH],
        partial_sbox: Column<Advice>,
        rc_a: [Column<Fixed>; WIDTH],
        rc_b: [Column<Fixed>; WIDTH],
    ) -> PoseidonConfig<F, WIDTH, RATE, L> {
        let pow5 = Pow5Chip::configure::<S>(meta, state, partial_sbox, rc_a, rc_b);
        PoseidonConfig {
            state,
            partial_sbox,
            rc_a,
            rc_b,
            pow5
        }
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        words: [AssignedCell<F, F>; L]
    ) -> Result<AssignedCell<F, F>, Error> {
        let pow5_chip = Pow5Chip::construct(self.config.pow5.clone());

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), words)
        // Ok(words[0].clone())
    }
}
