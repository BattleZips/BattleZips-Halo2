use halo2_gadgets::poseidon::primitives::ConstantLength;

use {
    crate::{
        chips::bitify::{BitifyConfig, Num2BitsChip},
        utils::{binary::BinaryValue, board::BOARD_SIZE},
    },
    halo2_gadgets::poseidon::{
        primitives::Spec,
        Hash, Pow5Chip, Pow5Config,
    },
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{AssignedCell, Chip, Layouter, Value},
        plonk::{
            Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance,
            Selector,
        },
        poly::Rotation,
    },
    std::marker::PhantomData,
};

/**
 * Compute the trace for the running sum of a shot circuit
 *
 * @param board - board state to check hits against flipped shot bit
 * @param shot - shot (contains only 1 flipped bit) to query for hit or miss
 * @return - array of 100 assignments for shot_commitment bit sum and board hit sum
 */
pub fn compute_shot_trace<F: FieldExt>(
    board: BinaryValue,
    shot: BinaryValue,
) -> [[F; BOARD_SIZE]; 2] {
    let mut hit_trace = Vec::<F>::new();
    let mut shot_trace = Vec::<F>::new();

    // assign first round manually
    hit_trace.push(F::from(board.value[0] && shot.value[0]));
    shot_trace.push(F::from(shot.value[0]));
    for i in 1..BOARD_SIZE {
        // hit_trace: if board and shot have flipped bit, prev hit_trace + 1 else prev hit trace
        let condition = board.value[i] && shot.value[i];
        let new_hit_trace = hit_trace[hit_trace.len() - 1] + F::from(condition);
        hit_trace.push(new_hit_trace);
        // shot_trace: prev shot_trace + shot_trace
        let new_shot_trace = shot_trace[shot_trace.len() - 1] + F::from(shot.value[i]);
        shot_trace.push(new_shot_trace);
    }
    [
        shot_trace.try_into().unwrap(),
        hit_trace.try_into().unwrap(),
    ]
}

/**
 * Storage for a proof that a shot hits/ misses a given board commitment
 *
 * @param num2bits - num2bits config for board and ship commitments
 * @param advice - advice columns shared throughout instructions/ chips/ regions of ShotChip
 * @param selectors - selectors used to toggle gates in ShotChip
 * @param fixed - fixed columns for constant values in ShotChip
 */
#[derive(Clone, Debug)]
pub struct ShotConfig<F: FieldExt> {
    pub num2bits: [BitifyConfig; 2],
    pub poseidon: Pow5Config<F, 3, 2>,
    pub input: Column<Advice>,
    pub advice: [Column<Advice>; 4],
    pub instance: Column<Instance>,
    pub fixed: [Column<Fixed>; 6],
    pub selectors: [Selector; 3],
    _marker: PhantomData<F>,
}

pub struct ShotChip<S: Spec<F, 3, 2>, F: FieldExt> {
    config: ShotConfig<F>,
    _marker: PhantomData<S>,
}

impl<S: Spec<F, 3, 2>, F: FieldExt> Chip<F> for ShotChip<S, F> {
    type Config = ShotConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

pub trait ShotInstructions<S: Spec<F, 3, 2>, F: FieldExt> {
    /**
     * Load the private advice inputs into the chip
     *
     * @param board_state - advice 100 bit number to decompose to serialized board state
     * @param board_commitment - instance poseidon hash of board_state
     * @param shot_commitment - instance 100 bit number (1 bit flipped) representing shot
     * @param hit - instance (constrained to be boolean) value conveying shot hit status
     * @return reference to assigned cells of each input in order above
     */
    fn load_advice(
        &self,
        layouter: &mut impl Layouter<F>,
        board_state: F,
        board_commitment: F,
        shot_commitment: F,
        hit: F,
    ) -> Result<[AssignedCell<F, F>; 4], Error>;

    /**
     * Decompose board_state, shot_commitment into 100 bits each
     * @dev order in arrays: [board_state, shot_commitment]
     *
     * @param num - assignements to state/ shot commitment values
     * @param bits - unassigned binary decomposition of assigned values
     * @return - assignments to decomposed bits ([board_state, shot_commitment])
     */
    fn decompose(
        &self,
        layouter: &mut impl Layouter<F>,
        num: [AssignedCell<F, F>; 2],
        bits: [[F; BOARD_SIZE]; 2],
    ) -> Result<[[AssignedCell<F, F>; BOARD_SIZE]; 2], Error>;

    /**
     * Perform the running sum constrains comparing the shot commitment and board state bits
     *
     * @param bits - references to decomposed LE binary of [board_state, shot_commitment]
     * @param trace to assign for
     *  - running sum of flipped bits in shot at each row
     *  - running sum of matching shot & board bits
     * @return reference to final values for [shot_sum, hit_sum]
     */
    fn running_sums(
        &self,
        layouter: &mut impl Layouter<F>,
        bits: [[AssignedCell<F, F>; BOARD_SIZE]; 2],
        trace: [[F; BOARD_SIZE]; 2],
    ) -> Result<[AssignedCell<F, F>; 2], Error>;

    /**
     * Apply constraints to the output of the running sum trace
     *
     * @param hit - reference to asssigned hit assertion inputted at start
     * @param output - reference to running sum outputs [shot_sum, hit_sum]
     * @return - ok if the synthesis executed successfully
     */
    fn running_sum_output(
        &self,
        layouter: &mut impl Layouter<F>,
        hit: AssignedCell<F, F>,
        output: [AssignedCell<F, F>; 2],
    ) -> Result<(), Error>;

    /**
     * Hash the private board state
     *
     * @param preimage - the private board state (bits2num'ed)
     * @return - assigned cell storing poseidon hash of the board state
     */
    fn hash_board(
        &self,
        layouter: &mut impl Layouter<F>,
        preimage: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

impl<S: Spec<F, 3, 2>, F: FieldExt> ShotChip<S, F> {
    pub fn new(config: ShotConfig<F>) -> Self {
        ShotChip {
            config,
            _marker: PhantomData,
        }
    }

    /**
     * Configure the computation space of the circuit & return ShotConfig
     */
    pub fn configure(meta: &mut ConstraintSystem<F>) -> ShotConfig<F> {
        // define advice
        let mut advice = Vec::<Column<Advice>>::new();
        for _ in 0..4 {
            let col = meta.advice_column();
            meta.enable_equality(col);
            advice.push(col);
        }
        let advice: [Column<Advice>; 4] = advice.try_into().unwrap();
        let input = meta.advice_column();
        meta.enable_equality(input);

        // define fixed
        let mut fixed = Vec::<Column<Fixed>>::new();
        for _ in 0..6 {
            let col = meta.fixed_column();
            fixed.push(col);
        }
        // poseidon rc_a: fixed[3..6]
        // poseidon rc_b: fixed[0..3]
        // fixed[0] has constant enabled
        let fixed: [Column<Fixed>; 6] = fixed.try_into().unwrap();
        meta.enable_constant(fixed[0]);

        // define instance
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // define selectors
        let mut selectors = Vec::<Selector>::new();
        for _ in 0..3 {
            selectors.push(meta.selector());
        }
        let selectors: [Selector; 3] = selectors.try_into().unwrap();

        // define bits2num chips
        let mut num2bits = Vec::<BitifyConfig>::new();
        for _ in 0..2 {
            num2bits.push(Num2BitsChip::<_, BOARD_SIZE>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ));
        }
        let num2bits: [BitifyConfig; 2] = num2bits.try_into().unwrap();

        // define poseidon hash chip
        let poseidon = Pow5Chip::<F, 3, 2>::configure::<S>(
            meta,
            [advice[0], advice[1], advice[2]],
            advice[3],
            [fixed[3], fixed[4], fixed[5]],
            [fixed[0], fixed[1], fixed[2]],
        );

        // define gates
        meta.create_gate("boolean hit assertion", |meta| {
            let assertion = meta.query_advice(input, Rotation::cur());
            let one = Expression::Constant(F::one());
            let constraint = (one - assertion.clone()) * assertion.clone();
            // constrain using selector[0]
            // - the asserted hit/miss value is a boolean (0 or 1)
            let selector = meta.query_selector(selectors[0]);
            Constraints::with_selector(selector, [("asserted hit value is boolean", constraint)])
        });

        meta.create_gate("shot running sum row", |meta| {
            // query cells used in gate
            let hit_bit = meta.query_advice(advice[0], Rotation::cur());
            let shot_bit = meta.query_advice(advice[1], Rotation::cur());
            let shot_sum = meta.query_advice(advice[2], Rotation::cur());
            let hit_sum = meta.query_advice(advice[3], Rotation::cur());
            let prev_shot_sum = meta.query_advice(advice[2], Rotation::prev());
            let prev_hit_sum = meta.query_advice(advice[3], Rotation::prev());
            // constraint expressions
            let shot_constraint = shot_bit.clone() + prev_shot_sum - shot_sum;
            let hit_constraint = hit_bit * shot_bit + prev_hit_sum - hit_sum;
            // constrain using selector[1]
            // - shot bit sum = shot bit count = prev shot bit sum
            // - if board hit sum = if board bit == 1 and shot bit == 1 increment by 1 from prev
            let selector = meta.query_selector(selectors[1]);
            Constraints::with_selector(
                selector,
                [
                    ("running sum of flipped bits in shot", shot_constraint),
                    ("running sum of hits against board", hit_constraint),
                ],
            )
        });

        meta.create_gate("constrain shot running sum output", |meta| {
            // query cells used in gate
            let hit_assertion = meta.query_advice(advice[0], Rotation::cur());
            let shot_count = meta.query_advice(advice[1], Rotation::cur());
            let hit_count = meta.query_advice(advice[2], Rotation::cur());
            // constraint expressions
            let shot_constraint = Expression::Constant(F::one()) - shot_count;
            let hit_constraint = hit_assertion - hit_count;
            // constrain using selector[2]
            // - shot_sum = 1
            // - hit_sum = hit_assertion
            let selector = meta.query_selector(selectors[2]);
            Constraints::with_selector(
                selector,
                [
                    ("Shot only fires at one board cell", shot_constraint),
                    (
                        "Public hit assertion matches private witness",
                        hit_constraint,
                    ),
                ],
            )
        });

        // return config
        ShotConfig {
            num2bits,
            poseidon,
            advice,
            input,
            instance,
            fixed,
            selectors,
            _marker: PhantomData,
        }
    }

    /**
     * Synthesize a proof of a valid board
     *
     * @param board - the board state in BinaryValue form for bits-> integer functions
     * @param shot - the shot commitment in BinaryValue form for bits-> integer functions
     * @param hit - true/ false assertion if shot produces hit on board
     * @return - Ok if synthesis executes successfully
     */
    pub fn synthesize(
        &self,
        mut layouter: impl Layouter<F>,
        board: BinaryValue,
        shot: BinaryValue,
        hit: BinaryValue,
    ) -> Result<(), Error> {
        // compute values to witness
        let board_state = F::from_u128(board.lower_u128());
        let board_commitment = board_state; // @dev to be used for signed poseidon hash
        let shot_commitment = F::from_u128(shot.lower_u128());
        let bits = [
            board.bitfield::<F, BOARD_SIZE>(),
            shot.bitfield::<F, BOARD_SIZE>(),
        ];
        let trace = compute_shot_trace::<F>(board, shot);
        // load inputs as advice
        let inputs = self.load_advice(
            &mut layouter,
            board_state,
            board_commitment,
            shot_commitment,
            F::from_u128(hit.lower_u128()),
        )?;
        // decompose board_state and ship_commitment into constrained bits
        let assigned_bits =
            self.decompose(&mut layouter, [inputs[0].clone(), inputs[2].clone()], bits)?;
        // synthesize running sum
        let running_sum_results = self.running_sums(&mut layouter, assigned_bits, trace)?;
        // constrain results of running sum
        self.running_sum_output(&mut layouter, inputs[3].clone(), running_sum_results)?;
        // hash board state
        let hashed_state = self.hash_board(&mut layouter, inputs[1].clone())?;
        // export public values
        layouter.constrain_instance(hashed_state.cell(), self.config.instance, 0)?;
        layouter.constrain_instance(inputs[2].cell(), self.config.instance, 1)?;
        layouter.constrain_instance(inputs[3].cell(), self.config.instance, 2)?;
        Ok(())
    }
}

impl<S: Spec<F, 3, 2>, F: FieldExt> ShotInstructions<S, F> for ShotChip<S, F> {
    fn load_advice(
        &self,
        layouter: &mut impl Layouter<F>,
        board_state: F,
        board_commitment: F,
        shot_commitment: F,
        hit: F,
    ) -> Result<[AssignedCell<F, F>; 4], Error> {
        Ok(layouter.assign_region(
            || "load private ShotChip advice values",
            |mut region| {
                let board_state = region.assign_advice(
                    || "assign board state",
                    self.config.input,
                    0,
                    || Value::known(board_state),
                )?;
                let board_commitment = region.assign_advice(
                    || "assign board commitment",
                    self.config.input,
                    1,
                    || Value::known(board_commitment),
                )?;
                let shot_commitment = region.assign_advice(
                    || "assign shot commitment",
                    self.config.input,
                    2,
                    || Value::known(shot_commitment),
                )?;
                let hit = region.assign_advice(
                    || "assign hit assertion",
                    self.config.input,
                    3,
                    || Value::known(hit),
                )?;
                self.config.selectors[0].enable(&mut region, 3)?;
                Ok([board_state, board_commitment, shot_commitment, hit])
            },
        )?)
    }

    fn decompose(
        &self,
        layouter: &mut impl Layouter<F>,
        num: [AssignedCell<F, F>; 2],
        bits: [[F; BOARD_SIZE]; 2],
    ) -> Result<[[AssignedCell<F, F>; BOARD_SIZE]; 2], Error> {
        // decompose board state
        let chip = Num2BitsChip::<F, BOARD_SIZE>::new(num[0].clone(), bits[0]);
        let board_state = chip.synthesize(
            self.config.num2bits[0],
            layouter.namespace(|| "board_state num2bits"),
        )?;
        // decompose shot commitment
        let chip = Num2BitsChip::<F, BOARD_SIZE>::new(num[1].clone(), bits[1]);
        let shot_commitment = chip.synthesize(
            self.config.num2bits[1],
            layouter.namespace(|| "shot_commitment bits2num"),
        )?;
        Ok([board_state, shot_commitment])
    }

    fn running_sums(
        &self,
        layouter: &mut impl Layouter<F>,
        bits: [[AssignedCell<F, F>; BOARD_SIZE]; 2],
        trace: [[F; BOARD_SIZE]; 2],
    ) -> Result<[AssignedCell<F, F>; 2], Error> {
        Ok(layouter.assign_region(
            || "shot running sum",
            |mut region| {
                // pad first row
                let mut shot_sum = region.assign_advice_from_constant(
                    || "pad bit sum column",
                    self.config.advice[2],
                    0,
                    F::zero(),
                )?;
                let mut hit_sum = region.assign_advice_from_constant(
                    || "pad shot hit sum column",
                    self.config.advice[3],
                    0,
                    F::zero(),
                )?;
                // assign rows
                for i in 0..BOARD_SIZE {
                    // permute bits for row
                    let x1 = bits[0][i].copy_advice(
                        || format!("copy board bit {}", i),
                        &mut region,
                        self.config.advice[0],
                        i + 1,
                    )?;
                    let x2 = bits[1][i].copy_advice(
                        || format!("copy shot bit {}", i),
                        &mut region,
                        self.config.advice[1],
                        i + 1,
                    )?;
                    // assign trace for row
                    shot_sum = region.assign_advice(
                        || format!("shot bit count sum {}", i),
                        self.config.advice[2],
                        i + 1,
                        || Value::known(trace[0][i]),
                    )?;
                    hit_sum = region.assign_advice(
                        || format!("board hit count sum {}", i),
                        self.config.advice[3],
                        i + 1,
                        || Value::known(trace[1][i]),
                    )?;
                    self.config.selectors[1].enable(&mut region, i + 1)?;
                }
                Ok([shot_sum, hit_sum])
            },
        )?)
    }

    fn running_sum_output(
        &self,
        layouter: &mut impl Layouter<F>,
        hit: AssignedCell<F, F>,
        output: [AssignedCell<F, F>; 2],
    ) -> Result<(), Error> {
        Ok(layouter.assign_region(
            || "shot running sum output checks",
            |mut region| {
                // permute advice into region
                hit.copy_advice(
                    || "permute hit assertion",
                    &mut region,
                    self.config.advice[0],
                    0,
                )?;
                output[0].copy_advice(
                    || "permute shot bit count",
                    &mut region,
                    self.config.advice[1],
                    0,
                )?;
                output[1].copy_advice(
                    || "permute board hits by shot count",
                    &mut region,
                    self.config.advice[2],
                    0,
                )?;
                self.config.selectors[2].enable(&mut region, 0)?;
                Ok(())
            },
        )?)
    }

    fn hash_board(
        &self,
        layouter: &mut impl Layouter<F>,
        preimage: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        // // input word
        let chip = Pow5Chip::construct(self.config.poseidon.clone());

        let hasher =
            Hash::<_, _, S, ConstantLength<1>, 3, 2>::init(chip, layouter.namespace(|| "hasher"))?;
        hasher.hash(layouter.namespace(|| "hash"), [preimage])
    }
}
