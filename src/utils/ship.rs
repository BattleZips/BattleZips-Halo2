use {
    crate::utils::{binary::BinaryValue, board::BOARD_SIZE},
    bitvec::prelude::*,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]

pub enum ShipType {
    Carrier,
    Battleship,
    Cruiser,
    Submarine,
    Destroyer,
}

impl ShipType {
    /**
     * Return the length of the ship given its type
     *
     * @return - ship length according to S: ShipType as a usize const
     */
    pub const fn length(self) -> usize {
        match self {
            ShipType::Carrier => 5,
            ShipType::Battleship => 4,
            ShipType::Cruiser => 3,
            ShipType::Submarine => 3,
            ShipType::Destroyer => 2,
        }
    }

    /**
     * Return the name of the ship given its type
     *
     * @return - name of the ship as a String
     */
    pub const fn name(self) -> &'static str {
        match self {
            ShipType::Carrier => "Aircraft Carrier",
            ShipType::Battleship => "Battleship",
            ShipType::Cruiser => "Cruiser",
            ShipType::Submarine => "Submarine",
            ShipType::Destroyer => "Destroyer",
        }
    }
}

/**
 * Definition of a ship's placement on a board
 */
#[derive(Clone, Copy, Debug)]
pub struct Ship {
    pub ship_type: ShipType,
    pub x: u8, // [0, 9]
    pub y: u8, // [0, 9]
    pub z: bool,
}

// basic access/ construction/ debugging functionality
impl Ship {
    /**
     * Construct a new Ship object given x, y, z notation + type
     *
     * @param S - the type of ship (affects length and can only be placed once per board)
     * @param x - horizontal coordinate of the ship head
     * @param y - vertical coordinate of the ship head
     * @param z - dictates whether ship extends from x, y horizontally or veritcally
     * @return - instantiated Ship object
     */
    pub fn new(ship_type: ShipType, x: u8, y: u8, z: bool) -> Ship {
        Self { ship_type, x, y, z }
    }

    /**
     * Render ASCII to the console representing the ship placement
     */
    pub fn print(self) {
        let bits = self.bits().value;
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
        lines.push(String::from(format!(
            "   -------------------- ({})",
            horizontal_label
        )));
        lines.push(String::from("    0 1 2 3 4 5 6 7 8 9"));
        for line in lines {
            println!("{}", line);
        }
    }
}

// use in battleship game
impl Ship {
    /**
     * Return a vector of the coordinates on the game board this ship covers
     *
     * @return - vector of ship_type.length() size containing assigned coordinates
     */
    pub fn coordinates(self) -> Vec<usize> {
        let length = self.ship_type.length();
        let mut coordinates = Vec::<usize>::new();
        for i in 0..length {
            coordinates.push(match self.z {
                true => (10 * self.x + self.y) as usize + i,
                false => (10 * self.y + self.x) as usize + i,
            });
        }
        coordinates
    }

    /**
     * Return a vector of the coordinates on the board explicitly ordered X horizontally Y vertically
     *
     * @return - vector of ship_type.length() size containing assigned coordinates
     */
    pub fn empirical_coordiantes(self) -> Vec<usize> {
        let length = self.ship_type.length();
        let mut coordinates = Vec::<usize>::new();
        for i in 0..length {
            coordinates.push((10 * self.y + self.x) as usize + i);
        }
        coordinates
    }

    /**
     * Export a ship's commitment decomposed to 100 bits
     *
     * @return - BitArray booleans representing serialized board state with placement as u256
     */
    pub fn bits(self) -> BinaryValue {
        let coordinates = self.coordinates();
        let mut state = bitarr![u64, Lsb0; 0; BOARD_SIZE];
        for coordinate in coordinates {
            state.get_mut(coordinate).unwrap().set(true);
        }
        BinaryValue::new(
            BitArray::<[u64; 4], Lsb0>::from([state.into_inner()[0], state.into_inner()[1], 0, 0])
        )
    }
}

// use in a halo 2 proof
impl Ship {
    /**
     * Export a horizontal and vertical bit commitment
     * @notice the unplaced orientation will be 0/ empty
     *
     * @return - array of two placements where one is 0
     */
    pub fn private_witness(self) -> [BinaryValue; 2] {
        let placement = self.bits();
        match self.z {
            true => [BinaryValue::empty(), placement],
            false => [placement, BinaryValue::empty()],
        }
    }
}
