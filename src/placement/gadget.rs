use {
    crate::{
        placement::chip::PlacementConfig,
        utils::{
            binary::{bits_to_field_elements, unwrap_bitvec},
            ship::ShipPlacement,
        },
    },
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{AssignedCell, Region, Value},
        plonk::Error,
    },
};

pub const BOARD_SIZE: usize = 100; // size of board (bits in integer commitments)

// defines array of 100 assigned bits in a column (little endian)
#[derive(Clone, Debug)]
pub struct PlacementBits<F: FieldExt>([AssignedCell<F, F>; BOARD_SIZE]);

impl<F: FieldExt> PlacementBits<F> {
    /**
     * Construct a new BoardState object
     * @param cells - 100 assigned binary cells
     * @return - BoardState object
     */
    pub fn from(cells: [AssignedCell<F, F>; BOARD_SIZE]) -> Self {
        PlacementBits(cells)
    }

    /**
     * Attempt to extract a bit window from the board state
     * @dev will throw error if bit window is out of bounds
     * @param S - the size of the bit window
     * @param offset - the board cell to start window forward look from
     * @return - array of length S containing consecutive AssignedCells in bit column
     */
    pub fn get_window<const S: usize>(
        self,
        offset: usize,
    ) -> Result<[AssignedCell<F, F>; S], String> {
        match offset % 10 + S > 9 || offset > 99 {
            true => Err("bit window out of bounds".to_string()),
            false => {
                let bits: [AssignedCell<F, F>; S] = self.0[offset..offset + S]
                    .to_vec()
                    .iter()
                    .map(|bit| bit.clone())
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

pub trait InstructionUtilities<F: FieldExt> {
    /**
     * Construct a new PlacementState object
     * @dev use assign_padding_row() in practice
     *
     * @param bit_sum - reference to assigned bit_sum cell
     * @param full_window_sum - reference to assigned full_bit_window cell
     * @return - BoardState object
     */
    fn new(bit_sum: AssignedCell<F, F>, full_window_sum: AssignedCell<F, F>) -> PlacementState<F>;

    /**
     * Adds a row of 0's to the start of the region to prevent unexpected
     * constraints by gates using Rotation::prev() in first row (first w/o padding)
     *
     * @param region - the "placement running sum trace" region to pad first row of
     * @param config - PlacementChip config holding advice columns to assign to
     * @return - if successful padding first row, return new PlacementState w/ cells assigned to 0
     */
    fn assign_padding_row<const S: usize>(
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
    ) -> Result<PlacementState<F>, Error>;

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
    fn permute_bits2num<const S: usize>(
        &mut self,
        bits: &PlacementBits<F>,
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
    ) -> Result<PlacementBits<F>, Error>;

    /**
     * Assign running sum trace as computed by PlacementGadget
     *
     * @param self - stores references for final bit_sum and full_bit_window values
     * @param region - the "placement running sum trace" region to assign values to
     * @param config - the PlacementChip config holding advice columns to assign to
     * @param gadget - holds precomputed values matching trace expected of constraints
     * @return - if successful, new PlacementState containing references to final sums
     */
    fn assign_running_sum_trace<const S: usize>(
        &mut self,
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
        gadget: &PlacementGadget<F, S>,
    ) -> Result<PlacementState<F>, Error>;
}

impl<F: FieldExt> InstructionUtilities<F> for PlacementState<F> {
    fn new(bit_sum: AssignedCell<F, F>, full_window_sum: AssignedCell<F, F>) -> Self {
        PlacementState {
            bit_sum,
            full_window_sum,
        }
    }

    fn assign_padding_row<const S: usize>(
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
        Ok(PlacementState::<F>::new(bit_sum, full_window_sum))
    }

    fn permute_bits2num<const S: usize>(
        &mut self,
        bits: &PlacementBits<F>,
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
    ) -> Result<PlacementBits<F>, Error> {
        let mut permuted: Vec<AssignedCell<F, F>> = Vec::<AssignedCell<F, F>>::new();
        for i in 0..bits.0.len() {
            let bit = &bits.0[i];
            permuted.push(bit.copy_advice(
                || format!("permute bit {}", i),
                region,
                config.advice[0],
                i + 1, // offset + 1 for padded row
            )?);
        }
        Ok(PlacementBits::from(
            permuted
                .iter()
                .map(|bit| bit.clone())
                .collect::<Vec<AssignedCell<F, F>>>()
                .try_into()
                .unwrap(),
        ))
    }

    fn assign_running_sum_trace<const S: usize>(
        &mut self,
        region: &mut Region<F>,
        config: &PlacementConfig<F, S>,
        gadget: &PlacementGadget<F, S>,
    ) -> Result<PlacementState<F>, Error> {
        // first iteration
        let mut bit_sum_cell = region.assign_advice(
            || format!("assign running sum (bit count) {}", 0),
            config.advice[1],
            1, // offset by 1 extra for padding row
            || Value::known(gadget.bit_sum[0]),
        )?;
        let mut full_window_sum_cell = region.assign_advice(
            || format!("assign running sum (full window count) {}", 0),
            config.advice[2],
            1, // offset by 1 extra for padding row
            || Value::known(gadget.full_window_sum[0]),
        )?;
        config.selectors[1].enable(region, 1)?;
        config.selectors[2].enable(region, 1)?;
        // iterate through trace
        // for offset in 2..=BOARD_SIZE {
        for offset in 2..=100{
            let adjusted_offset = offset - 1; // offset by 1 extra for padding row

            // assign trace
            bit_sum_cell = region.assign_advice(
                || format!("assign running sum (bit count) {}", adjusted_offset),
                config.advice[1],
                offset, 
                || Value::known(gadget.bit_sum[adjusted_offset]),
            )?;
            full_window_sum_cell = region.assign_advice(
                || format!("assign running sum (full window count) {}", adjusted_offset),
                config.advice[2],
                offset, // offset by 1 extra for padding row
                || Value::known(gadget.full_window_sum[adjusted_offset]),
            )?;
            // toggle selectors
            config.selectors[1].enable(region, offset)?;
            if offset % 10 + S >= 10 {
                config.selectors[3].enable(region, offset)?;
            } else {
                config.selectors[2].enable(region, offset)?;
            }
        }
        Ok(PlacementState {
            bit_sum: bit_sum_cell,
            full_window_sum: full_window_sum_cell,
        })
    }
}

/**
 * High level gadget used to drive a PlacementChip
 */
#[derive(Clone, Copy, Debug)]
pub struct PlacementGadget<F: FieldExt, const S: usize> {
    pub ship: ShipPlacement<S>, // object constructed from (x, y, z, len) to use ship
    pub bits: [F; BOARD_SIZE],           // little endian decomposition of placement commitment
    pub bit_sum: [F; BOARD_SIZE], // running sum of total flipped bits in `bits` array
    pub full_window_sum: [F; BOARD_SIZE], // running sum of total full bit windows of len `S`
}

impl<F: FieldExt, const S: usize> PlacementGadget<F, S> {
    /**
     * Given a ShipPlacement object, construct the running sum traces
     *
     * @param ship: ship helper object
     * @return - gadget containing values needed to use PlacementChip
     */
    pub fn new(ship: ShipPlacement<S>) -> Self {
        // encode ship placement for arithemtization
        let bits = bits_to_field_elements::<F, BOARD_SIZE>(unwrap_bitvec(ship.to_bits()));
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
            if i % 10 + S >= 10 {
                // permute case
                trace.push(trace[i - 1]);
            } else {
                // bit window check case
                trace.push(trace[i - 1] + increment(i))
            }
        }
        let full_window_sum: [F; BOARD_SIZE] = trace.try_into().unwrap();
        
        // //print
        // for i in 0..BOARD_SIZE {
        //     println!("=-=-=-=-=-=\nbit #{}: {:?}", i, bits[i]);
        //     println!("bit_sum: {:?}", bit_sum[i]);
        //     println!("full_window_sum: {:?}", full_window_sum[i]);
        // }

        // return object
        PlacementGadget {
            ship,
            bits,
            bit_sum,
            full_window_sum,
        }
    }
}
