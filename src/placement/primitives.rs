use {
    crate::{
        placement::chip::PlacementConfig,
        utils::{binary::BinaryValue, board::BOARD_SIZE},
    },
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{AssignedCell, Region, Value},
        plonk::Error,
    },
};

pub type AssignedBits<F> = [AssignedCell<F, F>; BOARD_SIZE];
pub type PlacementTrace<F> = [[F; BOARD_SIZE]; 2];

/**
 * Given a ShipPlacement object, construct the running sum traces
 *
 * @param ship - ship helper object
 * @return - bit_sum and full_bit_window cell values for assignment
 */
pub fn compute_placement_trace<F: FieldExt, const S: usize>(
    ship: BinaryValue,
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
