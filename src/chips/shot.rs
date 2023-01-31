use {
    crate::{
        chips::{
            bitify::{BitifyConfig, Num2BitsChip},
            pedersen::{PedersenCommitmentChip, PedersenCommitmentConfig},
        },
        utils::{binary::BinaryValue, board::BOARD_SIZE, pedersen::pedersen_commit},
    },
    halo2_proofs::{
        arithmetic::{CurveAffine, FieldExt},
        circuit::{AssignedCell, Chip, Layouter, Value},
        pasta::{group::Curve, pallas},
        plonk::{
            Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance,
            Selector, TableColumn,
        },
        poly::Rotation,
    },
};

/**
 * Compute the trace for the running sum of a shot circuit
 *
 * @param board - board state to check hits against flipped shot bit
 * @param shot - shot (contains only 1 flipped bit) to query for hit or miss
 * @return - array of 100 assignments for shot_commitment bit sum and board hit sum
 */
pub fn compute_shot_trace(
    board: BinaryValue,
    shot: BinaryValue,
) -> [[pallas::Base; BOARD_SIZE]; 2] {
    let mut hit_trace = Vec::<pallas::Base>::new();
    let mut shot_trace = Vec::<pallas::Base>::new();

    // assign first round manually
    hit_trace.push(pallas::Base::from(board.value[0] && shot.value[0]));
    shot_trace.push(pallas::Base::from(shot.value[0]));
    for i in 1..BOARD_SIZE {
        // hit_trace: if board and shot have flipped bit, prev hit_trace + 1 else prev hit trace
        let condition = board.value[i] && shot.value[i];
        let new_hit_trace = hit_trace[hit_trace.len() - 1] + pallas::Base::from(condition);
        hit_trace.push(new_hit_trace);
        // shot_trace: prev shot_trace + shot_trace
        let new_shot_trace = shot_trace[shot_trace.len() - 1] + pallas::Base::from(shot.value[i]);
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
pub struct ShotConfig {
    // chip configs
    pub num2bits: [BitifyConfig; 2],
    pub pedersen: PedersenCommitmentConfig,
    // columns
    pub advice: [Column<Advice>; 10],
    pub fixed: [Column<Fixed>; 8],
    pub table_idx: TableColumn,
    pub instance: Column<Instance>,
    // selectors
    pub selectors: [Selector; 3],
}

pub struct ShotChip {
    config: ShotConfig,
}

impl Chip<pallas::Base> for ShotChip {
    type Config = ShotConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

pub trait ShotInstructions {
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
        layouter: &mut impl Layouter<pallas::Base>,
        board_state: pallas::Base,
        board_commitment: [pallas::Base; 2],
        shot_commitment: pallas::Base,
        hit: pallas::Base,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 5], Error>;

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
        layouter: &mut impl Layouter<pallas::Base>,
        num: [AssignedCell<pallas::Base, pallas::Base>; 2],
        bits: [[pallas::Base; BOARD_SIZE]; 2],
    ) -> Result<[[AssignedCell<pallas::Base, pallas::Base>; BOARD_SIZE]; 2], Error>;

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
        layouter: &mut impl Layouter<pallas::Base>,
        bits: [[AssignedCell<pallas::Base, pallas::Base>; BOARD_SIZE]; 2],
        trace: [[pallas::Base; BOARD_SIZE]; 2],
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 2], Error>;

    /**
     * Apply constraints to the output of the running sum trace
     *
     * @param hit - reference to asssigned hit assertion inputted at start
     * @param output - reference to running sum outputs [shot_sum, hit_sum]
     * @return - ok if the synthesis executed successfully
     */
    fn running_sum_output(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        hit: AssignedCell<pallas::Base, pallas::Base>,
        output: [AssignedCell<pallas::Base, pallas::Base>; 2],
    ) -> Result<(), Error>;

    /**
     * Compute the pedersen commitment to the board state
     *
     * @param board_state - base field element that can be decomposed into board state
     * @param board_commitment_trapdoor - scalar field element used to blind the commitment
     * @return - assigned cell storing the (x, y) coordinates of commitment on pallas curve
     */
    fn commit_board(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        board_state: AssignedCell<pallas::Base, pallas::Base>,
        board_commitment_trapdoor: pallas::Scalar,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 2], Error>;
}

impl ShotChip {
    pub fn new(config: ShotConfig) -> Self {
        ShotChip { config }
    }

    /**
     * Configure the computation space of the circuit & return ShotConfig
     */
    pub fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> ShotConfig {
        // define advice
        let mut advice = Vec::<Column<Advice>>::new();
        for _ in 0..10 {
            let col = meta.advice_column();
            meta.enable_equality(col);
            advice.push(col);
        }
        let advice: [Column<Advice>; 10] = advice.try_into().unwrap();
        let input = meta.advice_column();
        meta.enable_equality(input);

        // define fixed
        let mut fixed = Vec::<Column<Fixed>>::new();
        for _ in 0..8 {
            let col = meta.fixed_column();
            fixed.push(col);
        }

        // fixed[0] has constant enabled
        let fixed: [Column<Fixed>; 8] = fixed.try_into().unwrap();
        meta.enable_constant(fixed[0]);

        // define table column
        let table_idx = meta.lookup_table_column();

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
                meta, advice[5], advice[6], advice[7], fixed[0],
            ));
        }
        let num2bits: [BitifyConfig; 2] = num2bits.try_into().unwrap();

        // define pedersen chip
        let pedersen = PedersenCommitmentChip::configure(meta, advice, fixed, table_idx);

        // define gates
        meta.create_gate("boolean hit assertion", |meta| {
            let assertion = meta.query_advice(advice[4], Rotation::cur());
            let one = Expression::Constant(pallas::Base::one());
            let constraint = (one - assertion.clone()) * assertion.clone();
            // constrain using selector[0]
            // - the asserted hit/miss value is a boolean (0 or 1)
            let selector = meta.query_selector(selectors[0]);
            Constraints::with_selector(selector, [("asserted hit value is boolean", constraint)])
        });

        meta.create_gate("shot running sum row", |meta| {
            // query cells used in gate
            let hit_bit = meta.query_advice(advice[5], Rotation::cur());
            let shot_bit = meta.query_advice(advice[6], Rotation::cur());
            let shot_sum = meta.query_advice(advice[7], Rotation::cur());
            let hit_sum = meta.query_advice(advice[8], Rotation::cur());
            let prev_shot_sum = meta.query_advice(advice[7], Rotation::prev());
            let prev_hit_sum = meta.query_advice(advice[8], Rotation::prev());
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
            let hit_assertion = meta.query_advice(advice[5], Rotation::cur());
            let shot_count = meta.query_advice(advice[6], Rotation::cur());
            let hit_count = meta.query_advice(advice[7], Rotation::cur());
            // constraint expressions
            let shot_constraint = Expression::Constant(pallas::Base::one()) - shot_count;
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
            pedersen,
            advice,
            fixed,
            table_idx,
            instance,
            selectors,
        }
    }

    /**
     * Synthesize a proof of a valid board
     *
     * @param board - the board state in BinaryValue form for bits-> integer functions
     * @param board_commitment_trapdoor - the trapdoor for the board commitment
     * @param shot - the shot commitment in BinaryValue form for bits-> integer functions
     * @param hit - true/ false assertion if shot produces hit on board
     * @return - Ok if synthesis executes successfully
     */
    pub fn synthesize(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        board: BinaryValue,
        board_commitment_trapdoor: pallas::Scalar,
        shot: BinaryValue,
        hit: BinaryValue,
    ) -> Result<(), Error> {
        // compute values to witness
        let board_state = pallas::Base::from_u128(board.lower_u128());
        let board_commitment = {
            let commitment = pedersen_commit(&board_state, &board_commitment_trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            [x, y]
        };
        let shot_commitment = pallas::Base::from_u128(shot.lower_u128());
        let bits = [
            board.bitfield::<pallas::Base, BOARD_SIZE>(),
            shot.bitfield::<pallas::Base, BOARD_SIZE>(),
        ];
        let trace = compute_shot_trace(board, shot);
        // load inputs as advice
        let inputs = self.load_advice(
            &mut layouter,
            board_state,
            board_commitment,
            shot_commitment,
            pallas::Base::from_u128(hit.lower_u128()),
        )?;
        // decompose board_state and ship_commitment into constrained bits
        let assigned_bits =
            self.decompose(&mut layouter, [inputs[0].clone(), inputs[3].clone()], bits)?;
        // synthesize running sum
        let running_sum_results = self.running_sums(&mut layouter, assigned_bits, trace)?;
        // constrain results of running sum
        self.running_sum_output(&mut layouter, inputs[4].clone(), running_sum_results)?;
        // commit to board state
        let commitment =
            self.commit_board(&mut layouter, inputs[0].clone(), board_commitment_trapdoor)?;
        // export public values
        layouter.constrain_instance(commitment[0].cell(), self.config.instance, 0)?;
        layouter.constrain_instance(commitment[1].cell(), self.config.instance, 1)?;
        layouter.constrain_instance(inputs[3].cell(), self.config.instance, 2)?;
        layouter.constrain_instance(inputs[4].cell(), self.config.instance, 3)?;
        Ok(())
    }
}

impl ShotInstructions for ShotChip {
    fn load_advice(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        board_state: pallas::Base,
        board_commitment: [pallas::Base; 2],
        shot_commitment: pallas::Base,
        hit: pallas::Base,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 5], Error> {
        Ok(layouter.assign_region(
            || "load private ShotChip advice values",
            |mut region| {
                let board_state = region.assign_advice(
                    || "assign board state",
                    self.config.advice[4],
                    0,
                    || Value::known(board_state),
                )?;
                let x = region.assign_advice(
                    || "assign board state",
                    self.config.advice[4],
                    1,
                    || Value::known(board_commitment[0]),
                )?;
                let y = region.assign_advice(
                    || "assign board state",
                    self.config.advice[4],
                    2,
                    || Value::known(board_commitment[1]),
                )?;
                let shot_commitment = region.assign_advice(
                    || "assign shot commitment",
                    self.config.advice[4],
                    3,
                    || Value::known(shot_commitment),
                )?;
                let hit = region.assign_advice(
                    || "assign hit assertion",
                    self.config.advice[4],
                    4,
                    || Value::known(hit),
                )?;
                // enable selector to check hit is binary
                self.config.selectors[0].enable(&mut region, 4)?;
                Ok([board_state, x, y, shot_commitment, hit])
            },
        )?)
    }

    fn decompose(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        num: [AssignedCell<pallas::Base, pallas::Base>; 2],
        bits: [[pallas::Base; BOARD_SIZE]; 2],
    ) -> Result<[[AssignedCell<pallas::Base, pallas::Base>; BOARD_SIZE]; 2], Error> {
        // decompose board state
        let chip = Num2BitsChip::<pallas::Base, BOARD_SIZE>::new(num[0].clone(), bits[0]);
        let board_state = chip.synthesize(
            self.config.num2bits[0],
            layouter.namespace(|| "board_state num2bits"),
        )?;
        // decompose shot commitment
        let chip = Num2BitsChip::<pallas::Base, BOARD_SIZE>::new(num[1].clone(), bits[1]);
        let shot_commitment = chip.synthesize(
            self.config.num2bits[1],
            layouter.namespace(|| "shot_commitment bits2num"),
        )?;
        Ok([board_state, shot_commitment])
    }

    fn running_sums(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        bits: [[AssignedCell<pallas::Base, pallas::Base>; BOARD_SIZE]; 2],
        trace: [[pallas::Base; BOARD_SIZE]; 2],
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 2], Error> {
        Ok(layouter.assign_region(
            || "shot running sum",
            |mut region| {
                // pad first row
                let mut shot_sum = region.assign_advice_from_constant(
                    || "pad bit sum column",
                    self.config.advice[7],
                    0,
                    pallas::Base::zero(),
                )?;
                let mut hit_sum = region.assign_advice_from_constant(
                    || "pad shot hit sum column",
                    self.config.advice[8],
                    0,
                    pallas::Base::zero(),
                )?;
                // assign rows
                for i in 0..BOARD_SIZE {
                    // permute bits for row
                    let x1 = bits[0][i].copy_advice(
                        || format!("copy board bit {}", i),
                        &mut region,
                        self.config.advice[5],
                        i + 1,
                    )?;
                    let x2 = bits[1][i].copy_advice(
                        || format!("copy shot bit {}", i),
                        &mut region,
                        self.config.advice[6],
                        i + 1,
                    )?;
                    // assign trace for row
                    shot_sum = region.assign_advice(
                        || format!("shot bit count sum {}", i),
                        self.config.advice[7],
                        i + 1,
                        || Value::known(trace[0][i]),
                    )?;
                    hit_sum = region.assign_advice(
                        || format!("board hit count sum {}", i),
                        self.config.advice[8],
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
        layouter: &mut impl Layouter<pallas::Base>,
        hit: AssignedCell<pallas::Base, pallas::Base>,
        output: [AssignedCell<pallas::Base, pallas::Base>; 2],
    ) -> Result<(), Error> {
        Ok(layouter.assign_region(
            || "shot running sum output checks",
            |mut region| {
                // permute advice into region
                hit.copy_advice(
                    || "permute hit assertion",
                    &mut region,
                    self.config.advice[5],
                    0,
                )?;
                output[0].copy_advice(
                    || "permute shot bit count",
                    &mut region,
                    self.config.advice[6],
                    0,
                )?;
                output[1].copy_advice(
                    || "permute board hits by shot count",
                    &mut region,
                    self.config.advice[7],
                    0,
                )?;
                self.config.selectors[2].enable(&mut region, 0)?;
                Ok(())
            },
        )?)
    }

    fn commit_board(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        board_state: AssignedCell<pallas::Base, pallas::Base>,
        board_commitment_trapdoor: pallas::Scalar,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 2], Error> {
        let chip = PedersenCommitmentChip::new(self.config.pedersen.clone());
        let commitment = chip.synthesize(
            layouter.namespace(|| "pedersen"),
            &board_state,
            Value::known(board_commitment_trapdoor),
        )?;
        // return pedersen commitment points
        Ok([
            commitment.clone().inner().x(),
            commitment.clone().inner().y(),
        ])
    }
}
