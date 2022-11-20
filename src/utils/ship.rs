use {
    bitvec::prelude::*,
    crate::utils::binary::{bits2num, unwrap_bitvec}
};

/**
 * Definition of a ship's placement on a board
 */
#[derive(Clone, Copy, Debug)]
pub struct ShipPlacement<const S: usize> {
    pub x: u8, // [0, 9]
    pub y: u8, // [0, 9]
    pub z: bool,
}

// definition of ship utility functions used in rational operation of circuit
pub trait PlacementUtilities<const S: usize> {

    /**
     * Construct a new ShipData object according to a given spec
     * @dev - use ShipData::valid() to check whether a ship's placement is valid
     *
     * @param ship_type - the type of ship (affects length and can only be placed once per board)
     * @param x - horizontal coordinate of the ship head
     * @param y - vertical coordinate of the ship head
     * @param z - dictates whether ship extends from x, y horizontally or veritcally
     * @return - instantiated ShipData object containing input parameters for future use
     */
    fn construct(x: u8, y: u8, z: bool) -> ShipPlacement<S>;

    /**
     * Export the coordinates the ship is placed on as a vector
     * @notice arrange byte order based on horizontal/ vertical orientation
     *     - ex: [x: 4, y: 7] - return: z = true { 74 } else { 47 }
     * @return - vector (of the length of the ship) of consecutive cells containing ship
     */
    fn to_coordinates(self) -> [u8; S];

    /**
     * Export the bitvec representation of the ship placement
     * @notice bits ordered according to horizontal/ vertical orientation
     *     - ex: [x: 1, y: 0, z: 0, l: 4] -> bits flipped @ [10, 20, 30, 40]
     *     - ex: [x: 1, y: 0, z: 1, l: 4] -> bits flipped @ [10, 11, 12, 13]
     * @return - 100 bit long array of ship arrangement
     */
    fn to_bits(self) -> BitVec<u8>;

    /**
     * Export the bitvec representation of the ship placement
     *
     * @param vertical - if true, export vertical orientation, else export horizontal
     * @return - 128 bit integer encoded board (really 100 bits)
     */
    fn to_decimal(self) -> u128;

    /**
     * Render ASCII to the console representing the ship placement
     */
    fn print(self);
}

// Implementation of ship utility functions used in rational operation of circuit
impl<const S: usize> PlacementUtilities<S> for ShipPlacement<S> {
    
    fn construct(x: u8, y: u8, z: bool) -> ShipPlacement<S> {
        ShipPlacement { x, y, z }
    }

    fn to_coordinates(self) -> [u8; S] {
        let mut coordinates = vec![0u8; S];
        for i in 0..S {
            // compute cell
            coordinates[i] = if self.z {
                10 * self.x + self.y + i as u8
            } else {
                10 * self.y + self.x + i as u8
            }
        }
        coordinates.try_into().unwrap()
    }

    fn to_bits(self) -> BitVec<u8> {
        let coordinates = self.to_coordinates();
        let mut board = 0u128.to_le_bytes().view_bits::<Lsb0>()[..100].to_bitvec();
        for coordinate in coordinates {
            board.set(coordinate as usize, true);
        }
        // @dev need better use of endianness
        board
    }

    fn to_decimal(self) -> u128 {
        let mut bits = self.to_bits();
        bits.reverse(); // @dev poor understanding of endianness :,(
        bits2num(&bits)
    }

    fn print(self) {
        const BOARD_SIZE: usize = 100;
        let bits = unwrap_bitvec::<BOARD_SIZE>(self.to_bits());
        let mut lines = Vec::<String>::new();
        for i in 0..BOARD_SIZE {
            if i % 10 == 0 {
                let mut out = format!("{} |", i / 10);
                for j in 0..10 {
                    out = format!("{} {}", out, bits[i + j] as u8);
                }
                lines.push(out);
            }
        }
        let horizontal_label = if self.z { "Y" } else { "X" };
        let vertical_label = if self.z { "X" } else { "Y" };

        lines.push(String::from(format!(" ({})", vertical_label)));
        lines.reverse();
        lines.push(String::from(format!("   -------------------- ({})", horizontal_label)));
        lines.push(String::from("    0 1 2 3 4 5 6 7 8 9"));

        for line in lines {
            println!("{}", line);
        }
    }
}

// definition of ship test functionsused in malicious operation of circuit
pub trait TestUtilities<const S: usize> {

    /**
     * Add horizontal and vertical commitments together. return [H, V, Sum(H, V)]
     * 
     * @return - array of [H, V, Sum(H, V)]
     */
    fn transposed_to_decimal(self) -> [u128; 3];

    /**
     * Returns a bitvec decomposition of Sum(H, V)
     */
    fn transposed_to_bits(self) -> BitVec<u8>;
    
}

// Implementation of ship test functionsused in malicious operation of circuit
impl<const S: usize> TestUtilities<S> for ShipPlacement<S> {

    /**
     * Returns a bitvec decomposition of Sum(H, V)
     */
    fn transposed_to_bits(self) -> BitVec<u8> {
        let decimal = self.transposed_to_decimal();
        decimal[2].to_le_bytes().view_bits::<Lsb0>().to_owned()
    }

    /**
     * Add horizontal and vertical commitments together. return [H, V, Sum(H, V)]
     * 
     * @return - array of [H, V, Sum(H, V)]
     */
    fn transposed_to_decimal(self) -> [u128; 3] {
        let horizontal = ShipPlacement::<S>::construct(self.x, self.y, false).to_decimal();
        let vertical = ShipPlacement::<S>::construct(self.x, self.y, true).to_decimal();
        let sum = horizontal + vertical;
        vec![horizontal, vertical, sum].try_into().unwrap()
    }

   

}

