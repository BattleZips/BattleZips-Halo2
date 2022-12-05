use {
    crate::{
        utils::board::BOARD_SIZE,
        
    },
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::AssignedCell
    }
};

pub const CHIP_SIZE: u32 = 7; // circuit requires 2^7 rows

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
