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

/**
 * Return the length of the ship given its tuple index for placement
 *
 * @return - ship length given order in placement
 */
pub const fn get_ship_length(size: usize) -> usize {
    match size {
        0 => 5, // carrier
        1 => 4, // battleship
        2 => 3, // cruiser
        3 => 3, // submarine
        4 => 2, // destroyer
        _ => 0,
    }
}

/**
 * Return the name of the ship given its tuple index for placement
 *
 * @return - ship name given order in placement
 */
pub const fn get_ship_name(size: usize) -> &'static str {
    match size {
        0 => "Carrier",
        1 => "Battleship",
        2 => "Cruiser",
        3 => "Submarine",
        4 => "Destroyer",
        _ => "NULL",
    }
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
        let bits = self.bits(true).value;
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
     * @param transpose - if true, apply vertical transposition rule
     * @return - vector of ship_type.length() size containing assigned coordinates
     */
    pub fn coordinates(self, transpose: bool) -> Vec<usize> {
        // if transpose is toggled, serialze vertical ships differently
        let mut coordinates = Vec::<usize>::new();
        for i in 0..self.ship_type.length() {
            // compute coordinate point with index offset
            let x_i = if self.z { self.x } else { self.x + i as u8 };
            let y_i = if self.z { self.y + i as u8 } else { self.y };
            // serialize coordinate point
            let x = if transpose && self.z { x_i * 10 } else { x_i };
            let y = if transpose && self.z { y_i } else { y_i * 10 };
            // combine and store
            coordinates.push((x + y) as usize);
        }
        coordinates
    }

    /**
     * Export a ship's commitment decomposed to 100 bits
     *
     * @param transpose - if true, apply vertical transposition rule
     * @return - BitArray booleans representing serialized board state with placement as u256
     */
    pub fn bits(self, transpose: bool) -> BinaryValue {
        let coordinates = self.coordinates(transpose);
        let mut state = bitarr![u64, Lsb0; 0; BOARD_SIZE];
        for coordinate in coordinates {
            state.get_mut(coordinate).unwrap().set(true);
        }
        BinaryValue::new(BitArray::<[u64; 4], Lsb0>::from([
            state.into_inner()[0],
            state.into_inner()[1],
            0,
            0,
        ]))
    }
}

// use in a halo 2 proof
impl Ship {
    /**
     * Export a ship's commitment decomposed to 100 bits
     *
     * @param utility - the type of test case to apply to witness value returned
     *        use WitnessOption::Default to return a default witness
     *        otherwise used for testing malicious cases
     * @return - two placements computed according to ship x/y/z/orientation + utility selection
     */
    pub fn witness(self, utility: WitnessOption) -> [BinaryValue; 2] {
        match utility {
            WitnessOption::Default => self.default_witness(),
            WitnessOption::DualPlacement => self.dual_placement(),
            WitnessOption::Nonconsecutive => self.nonconsecutive(),
            WitnessOption::ExtraBit => self.extra_bit(),
            WitnessOption::Oversized => self.oversized(),
            WitnessOption::Undersized => self.undersized(),
        }
    }

    /**
     * Export a horizontal and vertical ship commitment
     * @notice the unplaced orientation will be 0/ empty
     *
     * @return - array of two placements where one is 0
     */
    fn default_witness(self) -> [BinaryValue; 2] {
        let placement = self.bits(true);
        match self.z {
            true => [BinaryValue::empty(), placement],
            false => [placement, BinaryValue::empty()],
        }
    }

    /**
     * Export a horizontal and vertical ship commitment manipulated so that the placement uses both H & V
     * @dev if carrier placed horizontally, bit 0 will be placed vertically and bits 1-4 will be placed horizontally
     *
     * @return - array of two placements manipulated to use both H & V as described
     */
    fn dual_placement(self) -> [BinaryValue; 2] {
        // get default placement
        let mut placement = self.default_witness();
        // get index of first bit
        let index = self.coordinates(true)[0];
        // move first bit from assigned placement commitment to empty placement commitment such that
        // (example h: empty)    ... 0 0 0 0 0 0 0 0 ... => ... 0 0 1 0 0 0 0 0 ...
        // (example v: assigned) ... 0 0 1 1 1 1 0 0 ... => ... 0 0 0 1 1 1 0 0 ...
        let (from, to) = if self.z { (0, 1) } else { (1, 0) };
        placement[to].value.get_mut(index).unwrap().set(true);
        placement[from].value.get_mut(index).unwrap().set(false);
        placement
    }

    /**
     * Export a horizontal or vertical ship commitment manupulated so that last bit is moved forward one
     * @dev does panic if using on 100th bit
     *
     * @return - array of two placements where non-0 is manipulated to have non-consecutive ship placement
     */
    fn nonconsecutive(self) -> [BinaryValue; 2] {
        // get default placement
        let mut placement = self.default_witness();
        // get index of last bit
        let index = self.coordinates(true)[self.ship_type.length() - 1];
        // get the placement commitment being mutated
        let target = if self.z { 1 } else { 0 };
        // move last bit such that ... 0 0 1 1 1 1 0 0 ... becomes ... 0 0 1 1 1 0 1 0 ...
        placement[target].value.get_mut(index).unwrap().set(false);
        placement[target]
            .value
            .get_mut(index + 1)
            .unwrap()
            .set(true);
        placement
    }

    /**
     * Export a horizontal or vertical ship commitment manupulated so that an extra bit is set nonconsecutively
     * @dev sets 0th bit to true - make sure placements not @ 0th bit or this does nothing
     *      make sure palcements not @ 1st bit or same as oversized()
     *
     * @return - array of two placements where non-0 is manipulated to have non-consecutive extra bit
     */
    fn extra_bit(self) -> [BinaryValue; 2] {
        // get default placement
        let mut placement = self.default_witness();
        // get the placement commitment being mutated
        let target = if self.z { 1 } else { 0 };
        // add bit to
        placement[target].value.get_mut(0).unwrap().set(true);
        placement
    }

    /**
     * Export a horizontal or vertical ship commitment manupulated so that the ship is one bit too long
     * @dev panic if using on 100th bit (index 99)
     *
     * @return - array of two placements where non-0 is manipulated to have consecutive extra bit (oversized placement)
     */
    fn oversized(self) -> [BinaryValue; 2] {
        // get default placement
        let mut placement = self.default_witness();
        // get index of last bit
        let index = self.coordinates(true)[self.ship_type.length() - 1];
        // get the placement commitment being mutated
        let target = if self.z { 1 } else { 0 };
        // add bit to end of non-0 placement to increase length
        placement[target]
            .value
            .get_mut(index + 1)
            .unwrap()
            .set(true);
        placement
    }

    /**
     * Export a horizontal or vertical ship commitment manupulated so that the ship is one bit too short
     *
     * @return - array of two placements where non-0 is manipulated to have undersized ship placement
     */
    fn undersized(self) -> [BinaryValue; 2] {
        // get default placement
        let mut placement = self.default_witness();
        // get index of last bit
        let index = self.coordinates(true)[self.ship_type.length() - 1];
        // get the placement commitment being mutated
        let target = if self.z { 1 } else { 0 };
        // remove bit from end of non-0 placement to decrease length
        placement[target].value.get_mut(index).unwrap().set(false);
        placement
    }
}

// Defines possible options for witness generation for a given ship placement
#[derive(Clone, Copy)]
pub enum WitnessOption {
    // place the ship as a normal player would
    Default,
    // input H/V commitments where if H first bit is set in V instead of H
    // @dev make sure to test on H = V to avoid considering how transpose factors in
    DualPlacement,
    // input H or V commitment that has nonconsecutive bits of correct ship size
    Nonconsecutive,
    // for a ship length N, input H or V commitment that has N consecutive bits and one extra
    // @dev sets 0th bit to true - make sure placements not @ 0th or 1st bit
    ExtraBit,
    // for ship length N, input H or V commitment that has N+1 bits consecutively
    Oversized,
    // for ship length N, input H or V commitment that has N-1 bits
    Undersized,
}

pub const DEFAULT_WITNESS_OPTIONS: [WitnessOption; 5] = [
    WitnessOption::Default,
    WitnessOption::Default,
    WitnessOption::Default,
    WitnessOption::Default,
    WitnessOption::Default,
];
