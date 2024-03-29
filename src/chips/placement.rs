use {
    crate::utils::{binary::BinaryValue, board::BOARD_SIZE},
    halo2_proofs::{
        arithmetic::{lagrange_interpolate, FieldExt},
        circuit::{AssignedCell, Chip, Layouter, Region, Value},
        plonk::{
            Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Selector,
        },
        poly::Rotation,
    },
    std::marker::PhantomData,
};

/**
 * Storage required to use a ship placement validity chip
 * @TODO: BETTER DOCS HERE
 * @param bits2num - the Bits2NumConfig struct holding columns & data needed to compose bits into a decimal value
 * @param advice - array of 3 columns used to compute board validity
 *     * [bits, bit_sum, full_window_sum]
 *     * row 0 is padding for gate constraints
 *     * rows 1-100 perform running sum operations on bits. last row constrains output
 * @param selectors - array of 5 selectors that toggle constraints in chip
 *     * [placement_orientation, bit_sum, bit_adjacency, adjacency_permute, constrain_trace]
 * @param ship - Object storing/ exporting ship positioning
 */
#[derive(Clone, Copy, Debug)]
pub struct PlacementConfig<F: FieldExt, const S: usize> {
    pub bits: Column<Advice>, // store permuted bit decomposition (sum H + V in s_permute)
    pub bit_sum: Column<Advice>, // store unning sum of flipped bits (H placement in s_permute)
    pub full_window_sum: Column<Advice>, // store running sum of full bit windows (V placement in s_permute)
    pub fixed: Column<Fixed>,            // fixed column for constant values
    pub s_input: Selector,               // permute H+V decomposition & constrain sum
    pub s_sum_bits: Selector,            // increment prev bit sum if current bit flipped
    pub s_adjacency: Selector, // count bits in bit window and increment prev window sum if full
    pub s_permute: Selector,   // copy previous window sum to current window sum
    pub s_constrain: Selector, // constrain full_window_sum to be 1 and bit_sum to be S
    _marker: PhantomData<F>,
}

pub struct PlacementChip<F: FieldExt, const S: usize> {
    config: PlacementConfig<F, S>,
}

// instructions used by the chip to synthesize the proof
pub trait PlacementInstructions<F: FieldExt, const S: usize> {
    /**
     * Copy in horizontal, vertical bits2num decomposition. Sum each bit for H+V to collapse
     * @dev since H or V is 0 this just permutes in the nonzero decomposition
     *
     * @param bits - array of bit values to assign for sum(h, v)
     * @param horizontal - assigned cells for bits2num decomposition of horizontal commitment
     * @param vertical - assigned cells for bits2num decomposition of horizontal commitment
     * @return - assigned cells where each row is constrained to be sum of H + V bits
     */
    fn load_bits(
        &self,
        layouter: &mut impl Layouter<F>,
        bits: &[F; BOARD_SIZE],
        horizontal: &AssignedBits<F>,
        vertical: &AssignedBits<F>,
    ) -> Result<AssignedBits<F>, Error>;

    /**
     * Generate the running sum for bit counts and full bit windows
     *
     * @param bits - 100 assigned bits to permute into this region
     * @param trace - values for running sum trace to witness
     * @return - reference to final assignments for running bit sums and full bit window sums
     */
    fn placement_sums(
        &self,
        layouter: &mut impl Layouter<F>,
        bits: &AssignedBits<F>,
        trace: &PlacementTrace<F>,
    ) -> Result<PlacementState<F>, Error>;

    /**
     * Constrain the witnessed running sum values for placement to be valid under game logic
     *
     * @param state - reference to assigned bit count and full bit window count cells
     */
    fn assign_constraint(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &PlacementState<F>,
    ) -> Result<(), Error>;
}

impl<F: FieldExt, const S: usize> Chip<F> for PlacementChip<F, S> {
    type Config = PlacementConfig<F, S>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt, const S: usize> PlacementChip<F, S> {
    pub fn new(config: PlacementConfig<F, S>) -> Self {
        PlacementChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        bits: Column<Advice>,
        bit_sum: Column<Advice>,
        full_window_sum: Column<Advice>,
        fixed: Column<Fixed>,
    ) -> PlacementConfig<F, S> {
        // define selectors
        let s_input = meta.selector();
        let s_sum_bits = meta.selector();
        let s_adjacency = meta.selector();
        let s_permute = meta.selector();
        let s_constrain = meta.selector();

        meta.create_gate("sum inputted H, V bits", |meta| {
            // retrieve witnessed cells
            // repurposing columns:
            // - bit_sum: holds horizontal bit decomposition
            // - full_window_sum: holds vertical bit decomposition
            // - bits: holds sum of h+v bit
            let horizontal = meta.query_advice(bit_sum, Rotation::cur());
            let vertical = meta.query_advice(full_window_sum, Rotation::cur());
            let sum = meta.query_advice(bits, Rotation::cur());
            // constrain sum == horizontal + vertical
            let selector = meta.query_selector(s_input);
            Constraints::with_selector(selector, [("h + v = sum", sum - (horizontal + vertical))])
        });

        // selector[1] gate: bit count running sum
        meta.create_gate("placement bit count", |meta| {
            // check that this row's bit count is sum of prev row's bit count + current row's bit value
            let bit = meta.query_advice(bits, Rotation::cur());
            // store running bit sum in advice[0]
            let prev = meta.query_advice(bit_sum, Rotation::prev());
            let sum = meta.query_advice(bit_sum, Rotation::cur());
            // constrain sum to be equal to bit + prev
            let selector = meta.query_selector(s_sum_bits);
            Constraints::with_selector(selector, [("Running Sum: Bits", bit + prev - sum)])
        });

        // selector[2] gate: full bit window running sum
        meta.create_gate("adjacency bit count", |meta| {
            // count the number of bits in this gate and the proceeding `S` rows in bit column (A^2)
            let mut bit_count = meta.query_advice(bits, Rotation::cur());
            for i in 1..S {
                let bit = meta.query_advice(bits, Rotation(i as i32));
                bit_count = bit_count + bit;
            }

            // query full bit window running sum at column (A^4)
            let prev_full_window_count = meta.query_advice(full_window_sum, Rotation::prev());
            let full_window_count = meta.query_advice(full_window_sum, Rotation::cur());

            /*
             * Raise a given expression to the given power
             *
             * @param base - the exponent base
             * @param pow - the power to raise the exponent base to
             * @return - the exponent base raised to power
             */
            let exp_pow = |base: Expression<F>, pow: usize| -> Expression<F> {
                let mut exp = base.clone();
                if pow == 0 {
                    exp = Expression::Constant(F::one())
                } else {
                    for _ in 2..=pow {
                        exp = exp.clone() * base.clone();
                    }
                }
                exp
            };

            /*
             * Given a bit count, return the interpolated incrementor
             * @dev expects input to be in range [0, S]
             * @todo load lookup table with coefficients
             *
             * @param x - the sum of the bit window to pass in
             * @return - a boolean expression showing whether or not X = S (can be added as incrementor)
             */
            let interpolate_incrementor = |x: Expression<F>| -> Expression<F> {
                // generate lagrange interpolation inputs
                // if ship length is 4, then [0->0, 1->0, 2->0, 3->0, 4->1]
                let mut points = Vec::<F>::new();
                let mut evals = Vec::<F>::new();
                for i in 0..=S {
                    points.push(F::from(i as u64));
                    evals.push(if i == S { F::one() } else { F::zero() });
                }
                let interpolated = lagrange_interpolate(&points, &evals);
                let mut interpolated_value = Expression::Constant(F::zero());
                for i in 0..interpolated.len() {
                    let x_pow = exp_pow(x.clone(), i);
                    interpolated_value =
                        interpolated_value.clone() + Expression::Constant(interpolated[i]) * x_pow;
                }
                interpolated_value
            };

            // return constraint:
            // bit_count = bit_count
            // - if bit_count == ship_len, running_sum = prev_running_sum + 1
            // - if bit_count != ship_len, running_sum = prev_running
            let selector = meta.query_selector(s_adjacency);
            let constraint = full_window_count.clone()
                - prev_full_window_count
                - interpolate_incrementor(bit_count);
            Constraints::with_selector(selector, [("Full Window Running Sum", constraint)])
        });

        // selector[3] gate: permute bit window running sum
        meta.create_gate("permute adjaceny bit count", |meta| {
            // confirm that the current row's adjacent bit count is the same as the previous rows
            // @dev used in rows where ship cannot be placed (offset % 10 + ship_length >= 10)
            // store running adjacency count in advice[2]
            let previous = meta.query_advice(full_window_sum, Rotation::prev());
            let current = meta.query_advice(full_window_sum, Rotation::cur());
            // constrain previous to equal current
            let selector = meta.query_selector(s_permute);
            Constraints::with_selector(
                selector,
                [("Premute Full Window Running Sum", previous - current)],
            )
        });

        // selector[4] gate: constrain running sum trace
        meta.create_gate("running sum constraints", |meta| {
            // confirm the final output of the placement computation does not violate ship placement rules
            // @dev constraining of sum(h,v) to bits2num output occurs in synthesis
            let ship_len = Expression::Constant(F::from(S as u64));
            let one = Expression::Constant(F::one());
            let bit_count = meta.query_advice(bit_sum, Rotation::cur());
            let full_window_count = meta.query_advice(full_window_sum, Rotation::cur());
            // - constrain bit count to be equal to S
            // - constrain exactly one full bit window
            let selector = meta.query_selector(s_constrain);
            Constraints::with_selector(
                selector,
                [
                    ("Placed ship of correct length", bit_count - ship_len),
                    ("One full bit window", full_window_count - one),
                ],
            )
        });

        // export config
        PlacementConfig {
            bits,
            bit_sum,
            full_window_sum,
            fixed,
            s_input,
            s_sum_bits,
            s_adjacency,
            s_permute,
            s_constrain,
            _marker: PhantomData,
        }
    }

    pub fn synthesize(
        &self,
        layouter: &mut impl Layouter<F>,
        ship: &BinaryValue,
        horizontal: &AssignedBits<F>,
        vertical: &AssignedBits<F>,
    ) -> Result<(), Error> {
        // load values in memoru
        let bits = ship.bitfield();
        let trace = compute_placement_trace::<F, S>(ship);
        // begin proof synthesis
        let assigned_bits = self.load_bits(layouter, &bits, horizontal, vertical)?;
        let running_sums = self.placement_sums(layouter, &assigned_bits, &trace)?;
        self.assign_constraint(layouter, &running_sums)?;
        Ok(())
    }
}

impl<F: FieldExt, const S: usize> PlacementInstructions<F, S> for PlacementChip<F, S> {
    fn load_bits(
        &self,
        layouter: &mut impl Layouter<F>,
        bits: &[F; BOARD_SIZE],
        horizontal: &AssignedBits<F>,
        vertical: &AssignedBits<F>,
    ) -> Result<AssignedBits<F>, Error> {
        Ok(layouter.assign_region(
            || "permute and collapse bit decompositions",
            |mut region: Region<F>| {
                let mut assigned = Vec::<AssignedCell<F, F>>::new();
                for i in 0..BOARD_SIZE {
                    self.config.s_input.enable(&mut region, i)?;
                    horizontal[i].copy_advice(
                        || format!("copy h bit #{}", i),
                        &mut region,
                        self.config.bit_sum,
                        i,
                    )?;
                    vertical[i].copy_advice(
                        || format!("copy v bit #{}", i),
                        &mut region,
                        self.config.full_window_sum,
                        i,
                    )?;
                    assigned.push(region.assign_advice(
                        || format!("collapse bit #{}", i),
                        self.config.bits,
                        i,
                        || Value::known(bits[i]),
                    )?);
                }
                Ok(AssignedBits::<F>::from(assigned.try_into().unwrap()))
            },
        )?)
    }

    fn placement_sums(
        &self,
        layouter: &mut impl Layouter<F>,
        bits2num: &AssignedBits<F>,
        trace: &PlacementTrace<F>,
    ) -> Result<PlacementState<F>, Error> {
        Ok(layouter.assign_region(
            || "placement running sum trace",
            |mut region: Region<F>| {
                // pad first row with 0's to prevent running sums'
                // Rotation::prev() from unintended consequences
                let mut state = PlacementState::<F>::assign_padding_row(&mut region, &self.config)?;
                // permute bits constrained in "load placement encoded values" region to this region
                let _ = state.permute_bits2num(&bits2num, &mut region, &self.config)?;
                // assign running sum trace across 100 (BOARD_SIZE) rows
                state = state.assign_running_sum_trace(&mut region, &self.config, &trace)?;
                Ok(state)
            },
        )?)
    }

    fn assign_constraint(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &PlacementState<F>,
    ) -> Result<(), Error> {
        Ok(layouter.assign_region(
            || "constrain running sum output",
            |mut region: Region<F>| {
                state.bit_sum.copy_advice(
                    || "copy bit sum total count to constraint region",
                    &mut region,
                    self.config.bit_sum,
                    0,
                )?;
                state.full_window_sum.copy_advice(
                    || "copy full bit window total count to constaint region",
                    &mut region,
                    self.config.full_window_sum,
                    0,
                )?;
                self.config.s_constrain.enable(&mut region, 0)?;
                Ok(())
            },
        )?)
    }
}

pub type AssignedBits<F> = [AssignedCell<F, F>; BOARD_SIZE];
pub type PlacementTrace<F> = [[F; BOARD_SIZE]; 2];

/**
 * Given a ShipPlacement object, construct the running sum traces
 *
 * @param ship - ship helper object
 * @return - bit_sum and full_bit_window cell values for assignment
 */
pub fn compute_placement_trace<F: FieldExt, const S: usize>(
    ship: &BinaryValue,
) -> PlacementTrace<F> {
    let bits = ship.bitfield::<F, BOARD_SIZE>();
    // compute bit_sum trace
    let mut trace: Vec<F> = Vec::<F>::new();
    trace.push(bits[0]);
    for i in 1..bits.len() {
        trace.push(bits[i] + trace[i - 1]);
    }
    let bit_sum: [F; BOARD_SIZE] = trace.try_into().unwrap();

    // function for returning increment
    // expects permute case check to be done lower in stack
    let increment = |offset: usize| {
        let bit_count = bits[offset..offset + S]
            .iter()
            .fold(F::zero(), |sum: F, elem: &F| sum + elem);
        let v = if bit_count.eq(&F::from(S as u64)) {
            F::one()
        } else {
            F::zero()
        };
        v
    };

    // compute full bit window trace
    trace = vec![increment(0)];
    for i in 1..bits.len() {
        if i % 10 + S > 10 {
            // permute case
            trace.push(trace[i - 1]);
        } else {
            // bit window check case
            trace.push(trace[i - 1] + increment(i))
        }
    }
    let full_window_sum: [F; BOARD_SIZE] = trace.try_into().unwrap();
    [bit_sum, full_window_sum]
}

// defines storage of final running bit and full bit window sums
pub struct PlacementState<F: FieldExt> {
    pub bit_sum: AssignedCell<F, F>,
    pub full_window_sum: AssignedCell<F, F>,
}

impl<F: FieldExt> PlacementState<F> {
    /**
     * Construct a new PlacementState object
     * @dev use assign_padding_row() in practice
     *
     * @param bit_sum - reference to assigned bit_sum cell
     * @param full_window_sum - reference to assigned full_bit_window cell
     * @return - BoardState object
     */
    pub fn new(bit_sum: AssignedCell<F, F>, full_window_sum: AssignedCell<F, F>) -> Self {
        PlacementState {
            bit_sum,
            full_window_sum,
        }
    }

    /**
     * Adds a row of 0's to the start of the region to prevent unexpected
     * constraints by gates using Rotation::prev() in first row (first w/o padding)
     *
     * @param region - the "placement running sum trace" region to pad first row of
     * @param config - PlacementChip config holding advice columns to assign to
     * @return - if successful padding first row, return new PlacementState w/ cells assigned to 0
     */
    pub fn assign_padding_row<const S: usize>(
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
    ) -> Result<Self, Error> {
        let bit_sum = region.assign_advice_from_constant(
            || "pad bit count running sum",
            config.bit_sum,
            0,
            F::zero(),
        )?;
        let full_window_sum = region.assign_advice_from_constant(
            || "pad full bit window running sum",
            config.full_window_sum,
            0,
            F::zero(),
        )?;
        Ok(PlacementState::<F>::new(bit_sum, full_window_sum))
    }

    /**
     * Permute the assigned cells from the bit2num region to the running sum trace region
     * @notice bits are permuted to advice[1][1..100] (row 0 is padding)
     *
     * @param self - PlacementState<F>
     * @param bits - assigned bit cells to copy advice from
     * @param region - the "placement running sum trace" region to assign values in
     * @param config - PlacementChip config holding advice columns to assign to
     * @param offset - the relative row in the region to assign to
     * @return - if successful, return assignments to the cells within trace region
     */
    pub fn permute_bits2num<const S: usize>(
        &mut self,
        bits: &AssignedBits<F>,
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
    ) -> Result<AssignedBits<F>, Error> {
        let mut permuted: Vec<AssignedCell<F, F>> = Vec::<AssignedCell<F, F>>::new();
        for i in 0..bits.len() {
            let bit = &bits[i];
            permuted.push(bit.copy_advice(
                || format!("permute bit {}", i),
                region,
                config.bits,
                i + 1, // offset + 1 for padded row
            )?);
        }
        Ok(AssignedBits::from(
            permuted
                .iter()
                .map(|bit| bit.clone())
                .collect::<Vec<AssignedCell<F, F>>>()
                .try_into()
                .unwrap(),
        ))
    }

    /**
     * Assign running sum trace as computed by PlacementGadget
     *
     * @param self - stores references for final bit_sum and full_bit_window values
     * @param region - the "placement running sum trace" region to assign values to
     * @param config - the PlacementChip config holding advice columns to assign to
     * @param trace - pre-computed assignements for bit_sum & full_window_sum
     * @return - if successful, new PlacementState containing references to final sums
     */
    pub fn assign_running_sum_trace<const S: usize>(
        &mut self,
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
        trace: &PlacementTrace<F>,
    ) -> Result<PlacementState<F>, Error> {
        // first iteration
        let mut bit_sum_cell = region.assign_advice(
            || format!("assign running sum (bit count) {}", 0),
            config.bit_sum,
            1, // offset by 1 extra for padding row
            || Value::known(trace[0][0]),
        )?;
        let mut full_window_sum_cell = region.assign_advice(
            || format!("assign running sum (full window count) {}", 0),
            config.full_window_sum,
            1, // offset by 1 extra for padding row
            || Value::known(trace[1][0]),
        )?;
        config.s_sum_bits.enable(region, 1)?;
        config.s_adjacency.enable(region, 1)?;
        // iterate through trace
        // for offset in 2..=BOARD_SIZE {
        for offset in 2..=BOARD_SIZE {
            let adjusted_offset = offset - 1; // offset by 1 extra for padding row

            // assign trace
            bit_sum_cell = region.assign_advice(
                || format!("assign running sum (bit count) {}", adjusted_offset),
                config.bit_sum,
                offset,
                || Value::known(trace[0][adjusted_offset]),
            )?;
            full_window_sum_cell = region.assign_advice(
                || format!("assign running sum (full window count) {}", adjusted_offset),
                config.full_window_sum,
                offset, // offset by 1 extra for padding row
                || Value::known(trace[1][adjusted_offset]),
            )?;

            // toggle selectors
            config.s_sum_bits.enable(region, offset)?;
            if adjusted_offset % 10 + S > 10 {
                config.s_permute.enable(region, offset)?;
            } else {
                config.s_adjacency.enable(region, offset)?;
            }
        }
        Ok(PlacementState {
            bit_sum: bit_sum_cell,
            full_window_sum: full_window_sum_cell,
        })
    }
}
