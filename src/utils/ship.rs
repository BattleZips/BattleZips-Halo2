use crate::board::gadget::BitCommitments;

use {
    crate::utils::{binary::bits2num, board::BOARD_SIZE},
    bitvec::prelude::*,
};

#[derive(Eq, PartialEq)]

pub enum ShipType {
    Carrier,
    Battleship,
    Cruiser,
    Submarine,
    Destroyer,
}

// type of a decomposed ship commitment
pub type ShipBits = BitArray<[u64; 4], Lsb0>;

// type of a ship commitment
pub type ShipCommitment = [u64; 4];

/**
 * Definition of a ship's placement on a board
 */
#[derive(Clone, Copy, Debug)]
pub struct Ship<const S: ShipType> {
    pub x: u8, // [0, 9]
    pub y: u8, // [0, 9]
    pub z: bool,
}

// basic access/ construction/ debugging functionality
impl<const S: ShipType> Ship<S> {
    /**
     * Construct a new Ship object given x, y, z notation + type
     *
     * @param S - the type of ship (affects length and can only be placed once per board)
     * @param x - horizontal coordinate of the ship head
     * @param y - vertical coordinate of the ship head
     * @param z - dictates whether ship extends from x, y horizontally or veritcally
     * @return - instantiated Ship object
     */
    pub fn new(x: u8, y: u8, z: bool) -> Ship<S> {
        Self { x, y, z }
    }

    /**
     * Return the length of the ship given its type
     *
     * @return - ship length according to S: ShipType as a usize const
     */
    pub const fn length(self) -> usize {
        match S {
            ShipType::Carrier => 5,
            ShipType::Battleship => 4,
            ShipType::Cruiser => 3,
            ShipType::Submarine => 3,
            ShipType::Destroyer => 2,
        }
    }

    /**
     * Render ASCII to the console representing the ship placement
     */
    pub fn print(self) {
        let bits = self.bits();
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

impl<const S: ShipType> Ship<S> {
    /**
     * Export a ship's commitment decomposed to 100 bits
     *
     * @return - BitArray of 100 booleans representing serialized board state with placement
     */
    pub fn bits(self) -> ShipBits {
        let length = self.length();
        let mut state = bitarr![u64, Lsb0; 0; BOARD_SIZE];
        for i in 0..length {
            // compute cell
            let coordinate = match self.z {
                true => (10 * self.x + self.y) as usize + i,
                false => (10 * self.y + self.x) as usize + i,
            };
            state.get_mut(coordinate).unwrap().set(true);
        }
        let state = state.into_inner();
        BitArray::<[u64; 4], Lsb0>::from([state[0], state[1], 0, 0])
    }
}
