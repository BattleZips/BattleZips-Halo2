use bitvec::prelude::*;
use crate::utils::binary::bits2num;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShipType {
    Carrier,
    Battleship,
    Destroyer,
    Submarine,
    Cruiser,
}

/**
 * Definition of a ship's placement on a board
 */
#[derive(Clone, Copy, Debug)]
pub struct Placement<const T: ShipType> {
    x: u8, // [0, 9]
    y: u8, // [0, 9]
    z: bool,
}

// Definition of the ship utilitity functions that operate on ship data

pub trait ShipUtilities<const T: ShipType> {
    /**
     * Given a ship type, return its length
     *
     * @param ship - the type of ship being queried for length
     * @return - the length of the ship [2, 5]
     */
    fn ship_len(ship: ShipType) -> u8;

    /**
     * Given a ship type, return its name as a string
     *
     * @param ship - the type of ship being queried for name
     * @return - the name of the ship as a string
     */
    fn ship_name(ship: ShipType) -> String;

    /**
     * Constructs an empty ship object
     */
    fn empty(ship: ShipType) -> Placement<T>;

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
    fn construct(ship_type: ShipType, x: u8, y: u8, z: bool) -> Placement<T>;

    // /**
    //  * Export the coordinates the ship is placed on as a vector
    //  *
    //  * @param vertical - if true, order traversal of each column before row
    //  *     - ex: [x: 4, y: 7] - return: if vertical { 74 } else { 47 }
    //  * @return - vector (of the length of the ship) of consecutive cells containing ship
    //  */
    // fn export_coordinates(self, vertical: bool) -> Vec<u8>;

    // /**
    //  * Export the bitvec representation of the ship placement
    //  *
    //  * @param vertical - if true, place ship with y axis horizontal and x vertical
    //  *     - ex: [x: 1, y: 0, z: 0, l: 4] -> bits flipped @ [10, 20, 30, 40]
    //  *     - ex: [x: 1, y: 0, z: 1, l: 4] -> bits flipped @ [10, 11, 12, 13]
    //  * @return - 100 bit long vector of ship arrangement
    //  */
    // fn export_bitvec(self, vertical: bool) -> BitVec<u8>;

    // /**
    //  * Export the bitvec representation of the ship placement
    //  *
    //  * @param vertical - if true, export vertical orientation, else export horizontal
    //  * @return - 128 bit integer encoded board (really 100 bits)
    //  */
    // fn export_element(self, vertical: bool) -> u128;
}

// Implementation of ship utility functions
impl<const T: ShipType> ShipUtilities<T> for Placement<T> {
    fn ship_len(ship: ShipType) -> u8 {
        match ship {
            ShipType::Carrier => 5,
            ShipType::Battleship => 4,
            ShipType::Destroyer => 3,
            ShipType::Submarine => 3,
            ShipType::Cruiser => 2,
        }
    }

    fn ship_name(ship: ShipType) -> String {
        let name = match ship {
            ShipType::Carrier => "Carrier",
            ShipType::Battleship => "Battleship",
            ShipType::Destroyer => "Destroyer",
            ShipType::Submarine => "Submarine",
            ShipType::Cruiser => "Cruiser",
        };
        name.to_string()
    }

    fn empty(ship: ShipType) -> Placement<T> {
        Placement {
            x: 0,
            y: 0,
            z: false,
        }
    }

    fn construct(ship_type: ShipType, x: u8, y: u8, z: bool) -> Placement<T> {
        Placement { x, y, z }
    }

    // fn export_coordinates(self, vertical: bool) -> Vec<u8> {
    //     let ship_length = ShipUtilities::ship_len(self.ship_type);
    //     let mut coordinates = vec![0u8, ship_length];
    //     for i in 0..ship_length {
    //         // compute cell
    //         let x = if self.placement.z == false {
    //             self.placement.x + i
    //         } else {
    //             self.placement.x
    //         };
    //         let y = if self.placement.z == false {
    //             self.placement.y
    //         } else {
    //             self.placement.y + i
    //         };
    //         // store cell depending on orientation
    //         coordinates[0] = if vertical == false {
    //             x * 10 + y
    //         } else {
    //             y * 10 + x
    //         }
    //     }
    //     coordinates
    // }

    // fn export_bitvec(self, vertical: bool) -> BitVec<u8> {
    //     let coordinates = self.export_coordinates(vertical);
    //     let mut board = 0u128.to_le_bytes().view_bits::<Lsb0>()[..100].to_bitvec();
    //     for coordinate in coordinates {
    //         board.set(coordinate as usize, true);
    //     }
    //     board
    // }

    // fn export_element(self, vertical: bool) -> u128 {
    //     bits2num(&self.export_bitvec(vertical))
    // }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn t0_general_use() {}

    #[test]
    fn t1_validity() {}

    #[test]
    fn t2_export_coordinates() {}
}
