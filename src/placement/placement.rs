// use crate::{
//     bits2num::bits2num::{Bits2NumConfig, Bits2NumChip},
//     utils::ship::{Placement, ShipType, ShipUtilities}
// };
use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance,
        Selector,
    },
    poly::Rotation,
};

use crate::{
    bits2num::bits2num::{Bits2NumChip, Bits2NumConfig},
    utils::{
        binary::{bits_to_field_elements, unwrap_bitvec},
        ship::ShipPlacement,
    },
};

const BOARD_SIZE: usize = 100;

/**
 * Storage required to use a ship placement validity chip
 *
 * @param bits2num - the Bits2NumConfig struct holding columns & data needed to compose bits into a decimal value
 * @param advice - array of 3 columns used to compute board validity
 *     * rows 0-99 perform running sum operations on bits. last row constrains output
 * @param q_binary_row - toggle to sum bits, count adjacency, etc.
 * @param q_constrain_placement - toggle to constrain output to be valid
 * @param ship - Object storing/ exporting ship positioning
 */
#[derive(Clone, Debug)]
pub struct PlacementConfig<F: FieldExt, const S: usize> {
    bits2num: Bits2NumConfig,
    advice: [Column<Advice>; 3],
    q_placement_orientation: Selector,
    q_bit_sum: Selector,
    q_bit_adjacency: Selector,
    q_adjacency_permute: Selector,
    q_constrain_placement: Selector,

    ship: ShipPlacement<S>,
    _marker: PhantomData<F>,
}

// The set of instructions required to prove a ship placement does not violate battleship rules
// @notice does not prevent overlap
// pub trait PlacementInstructions<F: FieldExt, const S: usize>: Chip<F> {}

pub struct PlacementChip<F: FieldExt, const S: usize> {
    config: PlacementConfig<F, S>,
}

// defines array of 100 assigned bits in a column (little endian)
pub struct BoardState<F: FieldExt> {
    pub bits: [AssignedCell<F, F>; BOARD_SIZE],
}

impl<F: FieldExt> BoardState<F> {
    /**
     * Construct a new BoardState object
     * @param cells - 100 assigned binary cells
     * @return - BoardState object
     */
    pub fn from(cells: [AssignedCell<F, F>; BOARD_SIZE]) -> Self {
        BoardState { bits: cells }
    }

    /**
     * Attempt to extract a bit window from the board state
     * @dev will throw error if bit window is out of bounds
     * @param S - the size of the bit window
     * @param offset - the board cell to start window forward look from
     * @return - array of length S containing consecutive AssignedCells in bit column
     */
    pub fn get_bit_window<const S: usize>(
        self,
        offset: usize,
    ) -> Result<[AssignedCell<F, F>; S], String> {
        match offset % 10 + S > 9 || offset > 99 {
            true => Err("bit window out of bounds".to_string()),
            false => {
                let bits: [AssignedCell<F, F>; S] = self.bits[offset..offset + S]
                    .to_vec()
                    .iter()
                    .map(|bit| *bit)
                    .collect::<Vec<AssignedCell<F, F>>>()
                    .try_into()
                    .unwrap();
                Ok(bits)
            }
        }
    }
}

// defines storage of final running bit and full bit window sums
pub struct PlacementState<F: FieldExt> {
    pub bit_sum: AssignedCell<F, F>,
    pub full_window_sum: AssignedCell<F, F>,
}

impl<F: FieldExt> PlacementState<F> {
    /**
     * Construct a new PlacementState object
     * @param bit_sum - reference to assigned bit_sum cell
     * @param full_window_sum - reference to assigned full_bit_window cell
     *
     * @return - BoardState object
     */
    pub fn from(bit_sum: AssignedCell<F, F>, full_window_sum: AssignedCell<F, F>) -> Self {
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
     */
    pub fn assign_padding_row<const S: usize>(
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
    ) -> Result<Self, Error> {
        let bit_sum = region.assign_advice_from_constant(
            || "pad bit count running sum",
            config.advice[1],
            0,
            F::zero(),
        )?;
        let full_window_sum = region.assign_advice_from_constant(
            || "pad full bit window running sum",
            config.advice[2],
            0,
            F::zero(),
        )?;
        Ok(PlacementState::<F>::from(bit_sum, full_window_sum))
    }

    /**
     * Permute the assigned cells from the bit2num region to the running sum trace region
     * @notice bits are permuted to advice[1][1..100] (row 0 is padding)
     *
     * @param bits - assigned bit cells to copy advice from
     * @param region - the "placement running sum trace" region to assign values in
     * @param config - PlacementChip config holding advice columns to assign to
     * @param offset - the relative row in the region to assign to
     * @return - if successful, return assignments to the cells within trace region
     */
    pub fn permute_bits2num<const S: usize>(
        &mut self,
        bits: &BoardState<F>,
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
    ) -> Result<BoardState<F>, Error> {
        let mut permuted: [Option<AssignedCell<F, F>>; BOARD_SIZE] = [None; BOARD_SIZE];
        for i in 0..bits.bits.len() {
            let bit = bits.bits[i];
            permuted[i] = Some(
                bit.copy_advice(
                    || format!("permute bit {}", i),
                    region,
                    config.advice[0],
                    i + 1, // offset + 1 for padded row
                )
                .unwrap(),
            );
        }

        Ok(BoardState::from(
            permuted
                .iter()
                .map(|bit| bit.unwrap())
                .collect::<Vec<AssignedCell<F, F>>>()
                .try_into()
                .unwrap(),
        ))
    }

    /**
     * Given the previous row assignment (as self) for running sums,
     * assign the next row with bit window fullness evaluation
     *
     * @param bits - assigned bit cells to copy advice from
     * @param region - the "placement running sum trace" region to assign values in
     * @param config - PlacementChip config holding advice columns to assign to
     * @param offset - the relative row in the region to assign to
     */
    pub fn assign_window_row<const S: usize>(
        &mut self,
        bits: &BoardState<F>,
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
        offset: usize,
    ) -> Result<PlacementState<F>, Error> {
        // access bit window
        let bit_window = bits.get_bit_window::<S>(offset).unwrap();
        let mut window_count = Value::known(F::zero());
        for bit in bit_window {
            window_count = window_count + bit.value();
        }
        // compute current bit sum
        let bit_sum_value = bit_window[0].value().copied() + self.bit_sum.value().copied();
        // compute increment on full bit window count
        let one = Value::known(F::one());
        let ship_len = Value::known(F::from(S as u64));
        // @notice conditional_increment breaks if window_count > ship_len, use constraints to prevent
        // 0 if window_count < ship len; 1 if window_count = ship_len
        let conditional_increment = one - one * (ship_len - window_count);
        let full_window_sum_value = self.full_window_sum.value().copied() + conditional_increment;

        // assign running sum of flipped bits in bits2num constrained value
        let bit_sum = region.assign_advice(
            || format!("assign running sum (bit count) {}", offset),
            config.advice[1],
            offset,
            || bit_sum_value,
        )?;
        // assign running sum of full bit windows
        let full_window_sum = region.assign_advice(
            || format!("assign running sum (full bit window count) {}", offset),
            config.advice[2],
            offset,
            || full_window_sum_value,
        )?;
        // toggle selector for adjacency gate for this row
        config.q_bit_adjacency.enable(region, offset);
        // toggle selector for bit sum for this row
        config.q_bit_sum.enable(region, offset);
        Ok(Self {
            bit_sum,
            full_window_sum,
        })
    }

    /**
     * Given the previous row assignment (as self) for running sums,
     * assign next row permuting prev bit window value to this row
     * @dev still sums total bit count
     *
     * @param bits - assigned bit cells to copy advice from
     * @param region - the "placement running sum trace" region to assign values in
     * @param config - PlacementChip config holding advice columns to assign to
     * @param offset - the relative row in the region to assign to
     */
    pub fn assign_permute_row<const S: usize>(
        &mut self,
        bits: &BoardState<F>,
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
        offset: usize,
    ) -> Result<PlacementState<F>, Error> {
        // compute current bit sum
        let bit_sum_value = bits.bits[0].value().copied() + self.bit_sum.value().copied();
        let full_window_sum_value = self.full_window_sum.value();
        // assign running sum of flipped bits in bits2num constrained value
        let bit_sum = region.assign_advice(
            || format!("assign running sum (bit count) {}", offset),
            config.advice[1],
            offset,
            || bit_sum_value,
        )?;
        let full_window_sum = region.assign_advice(
            || format!("assign running sum (full bit window count) {}", offset),
            config.advice[2],
            offset,
            || full_window_sum_value.copied(),
        )?;
        // toggle selector for bit permute for this row
        config.q_adjacency_permute.enable(region, offset);
        // toggle selector for bit sum for this row
        config.q_bit_sum.enable(region, offset);
        Ok(Self {
            bit_sum,
            full_window_sum,
        })
    }
}

pub trait PlacementInstructions<F: FieldExt, const S: usize> {
    /*
     * Loads decimal encoding of horizontal placement, vertical placement, and sum of the two
     * @dev uses x, y, z, l from Placement to construct
     *
     * @return - reference to assigned cells on which further constraints are performed
     */
    fn load_placement(
        &self,
        Layouter: &mut impl Layouter<F>,
    ) -> Result<[AssignedCell<F, F>; 3], Error>;

    /**
     * Generate a bits2num region and constrain it to equal a given assigned cell
     *
     * @param value - assigned call that bits2num should compose to (SUM(H, V))
     * @return - array of 100 assigned cells representing bits
     */
    fn synth_bits2num(
        &self,
        Layouter: &mut impl Layouter<F>,
        value: AssignedCell<F, F>,
    ) -> Result<BoardState<F>, Error>;

    /**
     * Generate the running sum for bit counts and full bit windows
     *
     * @param bits - 100 assigned bits to permute into this region
     * @return - reference to final assignments for running bit sums and full bit window sums
     */
    fn placement_sums(
        &self,
        Layouter: &mut impl Layouter<F>,
        bits: BoardState<F>,
    ) -> Result<PlacementState<F>, Error>;

    /**
     * Constrain the witnessed running sum values for placement to be valid under game logic
     *
     * @param board_values - [horizontal, vertical] assignments
     * @param state - reference to assigned bit count and full bit window count cells
     */
    fn assign_constraint(
        &self,
        layouter: &mut impl Layouter<F>,
        state: PlacementState<F>,
    ) -> Result<(), Error>;
}

impl<F: FieldExt, const S: usize> PlacementChip<F, S> {
    pub fn construct(config: PlacementConfig<F, S>) -> Self {
        PlacementChip { config }
    }

    /**
     * Configure the computation space of the circuit & return PlacementConfig
     */
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        ship: ShipPlacement<S>,
    ) -> PlacementConfig<F, S> {
        // define advice columns
        let advice = [meta.advice_column(); 3];
        for col in advice {
            meta.enable_equality(col);
        }
        // allocate fixed column for constants
        meta.enable_equality(meta.fixed_column());

        // bits2num region: advice[0]: bits; advice[1]: lc1; advice[2]: e2
        // placement input region: advice[0]: bits; advice[1]: bit count running sum; advice[2]: full bit window running sum
        // placement running sum region: advice[0]: sum; advice[1]: horizontal decimal; advice[2]: vertical decimal

        // define bits2num config
        let bits2num = Bits2NumChip::<_, BOARD_SIZE>::configure(meta);

        // define selectors
        let q_placement_orientation = meta.selector();
        let q_bit_sum = meta.selector();
        let q_bit_adjacency = meta.selector();
        let q_adjacency_permute = meta.selector();
        let q_constrain_placement = meta.selector();

        meta.create_gate("horizontal/ vertical placement constraint", |meta| {
            // retrieve witnessed cells
            let sum = meta.query_advice(advice[0], Rotation::cur());
            let horizontal = meta.query_advice(advice[1], Rotation::cur());
            let vertical = meta.query_advice(advice[2], Rotation::cur());
            // constain either horizontal or vertical placement to be 0
            let either_zero = horizontal.clone() * vertical.clone();
            // constrain sum == horizontal + vertical
            // toggled by q_placement_orientation
            let summed = sum - (horizontal.clone() + vertical.clone());
            let selector = meta.query_selector(q_placement_orientation);
            Constraints::with_selector(
                selector,
                [("Either h or v == 0", either_zero), ("h + v = sum", summed)],
            )
        });

        // define gates
        meta.create_gate("placement bit count", |meta| {
            // check that this row's bit count is sum of prev row's bit count + current row's bit value
            let bit = meta.query_advice(advice[0], Rotation::cur());
            // store running bit sum in advice[0]
            let prev = meta.query_advice(advice[1], Rotation::prev());
            let sum = meta.query_advice(advice[1], Rotation::cur());
            // return constraint:
            // - toggled by q_bit_sum
            // - constrain sum to be equal to bit + prev
            let selector = meta.query_selector(q_bit_sum);
            Constraints::with_selector(selector, [("Running Sum: Bits", bit + prev - sum)])
        });

        meta.create_gate("adjacenct bit count", |meta| {
            // count the number of bits in this gate and the proceeding `S` rows in bit column (A^2)
            let mut bit_count = meta.query_advice(advice[0], Rotation::cur());
            for i in 1..S {
                let bit = meta.query_advice(advice[0], Rotation(i as i32));
                bit_count = bit_count + bit;
            }
            // query full bit window running sum at column (A^4)
            let prev_running_sum = meta.query_advice(advice[2], Rotation::prev());
            let running_sum = meta.query_advice(advice[2], Rotation::cur());
            // fixed ship length
            let ship_len = Expression::Constant(F::from(S as u64));

            /*
             * Constrain the expected value for the full bit window running sum
             *
             * @param count - the sum of all flipped bits in the window being queried
             * @param prev - the previous running sum of all bit windows of length ship_len that were full
             * @param sum - current running sum of all bit windows of length ship_len that are full
             * @return 0 if [count != ship_len && prev == sum] or [count == ship_len && prev + 1 = sum ]
             */
            let running_sum_exp =
                |count: Expression<F>, prev: Expression<F>, sum: Expression<F>| {
                    // constant expressions
                    let ship_len = Expression::Constant(F::from(S as u64));
                    let one = Expression::Constant(F::one());
                    // variable expressions
                    let increment_case = prev.clone() + one.clone() - sum.clone();
                    let equal_case = prev.clone() - sum.clone();
                    let condition = one.clone() - one.clone() * (ship_len.clone() - count.clone());
                    // return expected constraint equation
                    condition.clone() * increment_case.clone()
                        + (one.clone() - condition.clone()) * equal_case.clone()
                };

            // return constraint:
            // bit_count = bit_count
            // - if bit_count == ship_len, running_sum = prev_running_sum + 1
            // - if bit_count != ship_len, running_sum = prev_running
            let selector = meta.query_selector(q_bit_adjacency);
            Constraints::with_selector(
                selector,
                [(
                    "Full Window Running Sum",
                    running_sum_exp(
                        bit_count.clone(),
                        prev_running_sum.clone(),
                        running_sum.clone(),
                    ),
                )],
            )
        });

        meta.create_gate("permute adjacent bit count", |meta| {
            // confirm that the current row's adjacent bit count is the same as the previous rows
            // @dev used in rows where ship cannot be placed (offset % 10 + ship_length >= 10)
            // store running adjacency count in advice[2]
            let previous = meta.query_advice(advice[2], Rotation::prev());
            let current = meta.query_advice(advice[2], Rotation::cur());
            // return constraint
            // - toggled by q_adjacency_permute
            // - constrain previous to equal current
            let selector = meta.query_selector(q_adjacency_permute);
            Constraints::with_selector(
                selector,
                [("Premute Full Window Running Sum", previous - current)],
            )
        });

        meta.create_gate("running sum constraints", |meta| {
            // confirm the final output of the placement computation does not violate ship placement rules
            // @dev constraining of sum(h,v) to bits2num output occurs in synthesis
            let ship_len = Expression::Constant(F::from(S as u64));
            let one = Expression::Constant(F::one());
            let bit_count = meta.query_advice(advice[1], Rotation::cur());
            let full_window_count = meta.query_advice(advice[2], Rotation::cur());
            // return constraint
            // - toggled by q_constrain_placement
            // - constrain bit count to be equal to S
            // - constrain exactly one full bit window
            let selector = meta.query_selector(q_constrain_placement);
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
            bits2num,
            advice,
            q_placement_orientation,
            q_bit_sum,
            q_bit_adjacency,
            q_adjacency_permute,
            q_constrain_placement,
            ship,
            _marker: PhantomData,
        }
    }

    pub fn synthesize(&self, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let placement_commitments = self.load_placement(&mut layouter)?;
        let bits = self.synth_bits2num(&mut layouter, placement_commitments[0])?;
        let running_sums = self.placement_sums(&mut layouter, bits)?;
        self.assign_constraint(&mut layouter, running_sums);
        Ok(())
    }
}

impl<F: FieldExt, const S: usize> PlacementInstructions<F, S> for PlacementChip<F, S> {
    fn load_placement(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<[AssignedCell<F, F>; 3], Error> {
        // variables used to construct witness
        let decimal = self.config.ship.to_decimal();
        let horizontal = if self.config.ship.z {
            Value::known(F::from_u128(decimal))
        } else {
            Value::known(F::zero())
        };
        let vertical = if self.config.ship.z {
            Value::known(F::zero())
        } else {
            Value::known(F::from_u128(decimal))
        };
        let sum = horizontal + vertical;
        // storage variable for assigned cell holding sum(h, v) to be constrained to bits2num
        let mut assigned: [AssignedCell<F, F>; 3] = layouter.assign_region(
            || "load placement encoded values",
            |region: Region<F>| {
                self.config.q_placement_orientation.enable(&mut region, 0);
                let sum = region.assign_advice(
                    || "sum of h & v placements",
                    self.config.advice[0],
                    0,
                    || sum,
                )?;
                let horizontal = region.assign_advice(
                    || "horizontal placement",
                    self.config.advice[1],
                    0,
                    || horizontal,
                )?;
                let vertical = region.assign_advice(
                    || "vertical placements",
                    self.config.advice[2],
                    0,
                    || vertical,
                )?;
                Ok([sum, horizontal, vertical])
            },
        )?;
        Ok(assigned)
    }

    fn synth_bits2num(
        &self,
        layouter: &mut impl Layouter<F>,
        value: AssignedCell<F, F>,
    ) -> Result<BoardState<F>, Error> {
        let bits: [F; BOARD_SIZE] =
            bits_to_field_elements::<F, BOARD_SIZE>(unwrap_bitvec(self.config.ship.to_bits()));
        let bits2num = Bits2NumChip::<F, BOARD_SIZE>::new(value, bits);
        let assigned_bits =
            bits2num.synthesize(self.config.bits2num, layouter.namespace(|| "bits2num"))?;
        Ok(BoardState::<F>::from(assigned_bits))
    }

    fn placement_sums(
        &self,
        layouter: &mut impl Layouter<F>,
        bits2num: BoardState<F>,
    ) -> Result<PlacementState<F>, Error> {
        Ok(layouter.assign_region(
            || "placement running sum trace",
            |mut region: Region<F>| {
                // pad first row with 0's to prevent running sums'
                // Rotation::prev() from unintended consequences
                let mut state = PlacementState::<F>::assign_padding_row(&mut region, &self.config)?;
                // permute bits constrained in "load placement encoded values" region to this region
                let bits = state.permute_bits2num(&bits2num, &mut region, &self.config)?;
                // assign running sum trace across 100 (BOARD_SIZE) rows
                let window_condition = |offset: usize| offset % 10 + S < 10;
                for i in 0..BOARD_SIZE {
                    if window_condition(i) {
                        // assign row that can increment full bit window running sum
                        state =
                            state.assign_window_row::<S>(&bits, &mut region, &self.config, i)?;
                    } else {
                        // assign row that can only increment total bit sum
                        state =
                            state.assign_permute_row::<S>(&bits, &mut region, &self.config, i)?;
                    }
                }
                Ok(state)
            },
        )?)
    }

    fn assign_constraint(
        &self,
        layouter: &mut impl Layouter<F>,
        state: PlacementState<F>,
    ) -> Result<(), Error> {
        Ok(layouter.assign_region(
            || "constrain running sum output",
            |mut region: Region<F>| {
                state.bit_sum.copy_advice(
                    || "copy bit sum total count to constraint region",
                    &mut region,
                    self.config.advice[1],
                    0,
                );
                state.full_window_sum.copy_advice(
                    || "copy full bit window total count to constaint region",
                    &mut region,
                    self.config.advice[1],
                    0,
                );
                self.config.q_constrain_placement.enable(&mut region, 0);
                Ok(())
            },
        )?)
    }
}
