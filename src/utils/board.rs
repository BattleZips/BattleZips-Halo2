use {
    crate::utils::{
        binary::BinaryValue,
        ship::{Ship, ShipType},
    },
    bitvec::prelude::*,
    halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3, Spec},
    halo2_proofs::{
        arithmetic::{Field, FieldExt},
        pasta::Fp,
    },
    std::ops::{Index, IndexMut},
};

pub const BOARD_SIZE: usize = 100;

// contains all 5 ship commitments
#[derive(Clone, Copy, Debug)]
pub struct Deck {
    pub carrier: Option<Ship>,
    pub battleship: Option<Ship>,
    pub cruiser: Option<Ship>,
    pub submarine: Option<Ship>,
    pub destroyer: Option<Ship>,
}

impl Deck {
    /**
     * Return an empty deck
     *
     * @return - Board where commitment = 0 and all deck options are None
     */
    pub fn new() -> Self {
        Deck {
            carrier: None,
            battleship: None,
            cruiser: None,
            submarine: None,
            destroyer: None,
        }
    }

    /**
     * Return a deck initialized with valid placements hard-coded
     *
     * @return - a deck with 5 valid & predictably placed ships
     */
    pub fn default() -> Self {
        let mut deck = Deck::new();
        deck.add(Ship::new(ShipType::Carrier, 0, 0, false));
        deck.add(Ship::new(ShipType::Battleship, 0, 1, false));
        deck.add(Ship::new(ShipType::Cruiser, 0, 2, false));
        deck.add(Ship::new(ShipType::Submarine, 0, 3, false));
        deck.add(Ship::new(ShipType::Destroyer, 0, 4, false));
        deck
    }

    /**
     * Selectively place ships onto the board (instead of all 5)
     * @dev index corresponds to [carrier, battleship, cruiser, submarine, destroyer]
     *
     * @param ships - array of optional ship placements
     */
    pub fn from(ships: [Option<(u8, u8, bool)>; 5]) -> Self {
        let mut deck = Deck::new();
        if let Some((x, y, z)) = ships[0] {
            deck.add(Ship::new(ShipType::Carrier, x, y, z));
        }
        if let Some((x, y, z)) = ships[1] {
            deck.add(Ship::new(ShipType::Battleship, x, y, z));
        }
        if let Some((x, y, z)) = ships[2] {
            deck.add(Ship::new(ShipType::Cruiser, x, y, z));
        }
        if let Some((x, y, z)) = ships[3] {
            deck.add(Ship::new(ShipType::Submarine, x, y, z));
        }
        if let Some((x, y, z)) = ships[4] {
            deck.add(Ship::new(ShipType::Destroyer, x, y, z));
        }
        deck
    }

    /**
     * Return an iterable reference to ships in enum order
     *
     * @return - array of references to optional ship values
     */
    pub fn iterator(&self) -> [Option<Ship>; 5] {
        [
            self.carrier,
            self.battleship,
            self.cruiser,
            self.submarine,
            self.destroyer,
        ]
    }

    /**
     * Add a new ship of given type, or overwrite current ship of given type
     *
     * @param ship - the definiton of the ship to add to the deck
     */
    pub fn add(&mut self, ship: Ship) {
        self[ship.ship_type] = Some(ship);
    }

    /**
     * Remove a ship of a given type if it is in the deck
     *
     * @param ship - the type of ship to remove from the deck
     */
    pub fn remove(&mut self, ship: ShipType) {
        self[ship] = None;
    }
}

impl Index<ShipType> for Deck {
    type Output = Option<Ship>;
    fn index(&self, index: ShipType) -> &Option<Ship> {
        match index {
            ShipType::Carrier => &self.carrier,
            ShipType::Battleship => &self.battleship,
            ShipType::Cruiser => &self.cruiser,
            ShipType::Submarine => &self.submarine,
            ShipType::Destroyer => &self.destroyer,
        }
    }
}

impl IndexMut<ShipType> for Deck {
    fn index_mut(&mut self, index: ShipType) -> &mut Option<Ship> {
        match index {
            ShipType::Carrier => &mut self.carrier,
            ShipType::Battleship => &mut self.battleship,
            ShipType::Cruiser => &mut self.cruiser,
            ShipType::Submarine => &mut self.submarine,
            ShipType::Destroyer => &mut self.destroyer,
        }
    }
}

// Definition of all state data needed to create board commitments
#[derive(Clone, Copy, Debug)]
pub struct Board {
    pub ships: Deck,
    pub state: BinaryValue,
}

// Constructor utilities
impl Board {
    /**
     * Build an empty board object and return
     *
     * @return - Board where commitment = 0 and all deck options are None
     */
    pub fn new() -> Self {
        Board {
            ships: Deck::new(),
            state: BinaryValue::empty(),
        }
    }

    /**
     * Build a board object and place based on ship assignments in deck
     * @dev can place in any combination of ships
     *
     * @param deck - optional assignments for each ship
     * @return - Board where state is generated from assignments in deck input
     */
    pub fn from(deck: &Deck) -> Self {
        let mut board = Board::new();
        for ship in deck.iterator() {
            if ship.is_some() {
                _ = board.place(ship.unwrap());
            };
        }
        board
    }
}

// State access utilities
impl Board {
    /**
     * Determine whether or not a given ship will cause a collision when placed on board
     *
     * @param ship - the ship to check for placement on board
     * @return - true if the placement is invalid/ collides with existing ship, false otherwise
     */
    pub fn check_collisions(self, ship: Ship) -> bool {
        let coordinates = ship.coordinates(true);
        let mut collision = false;
        for coordinate in coordinates {
            let cell = self.state.value[coordinate];
            collision = collision && cell;
        }
        collision
    }

    /**
     * Format the shot commitments as needed for the private witness inputs for a Board proof
     *
     * @return - array of H/V shot commitments values for each ship to witness
     */
    pub fn witness(self) -> [BinaryValue; 10] {
        let mut full_witness = Vec::<BinaryValue>::new();
        for ship in self.ships.iterator() {
            let witness = if ship.is_none() {
                [BinaryValue::empty(), BinaryValue::empty()]
            } else {
                ship.unwrap().private_witness()
            };
            full_witness.push(witness[0]);
            full_witness.push(witness[1]);
        }
        full_witness.try_into().unwrap()
    }

    /**
     * Returns ship commitments for board as field elements
     *
     * @return - witness return values as field elements
     */
    pub fn witness_field<F: FieldExt>(self) -> [F; 10] {
        self.witness()
            .iter()
            .map(|commitment| F::from_u128(commitment.lower_u128()))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap()
    }

    /**
     * Returns ship commitments as decomposed 100-bit arrays
     *
     * @return - binary decompositions of each placement on a given prime field
     */
    pub fn witness_decompose<F: FieldExt>(self) -> [[F; BOARD_SIZE]; 10] {
        self.witness()
            .iter()
            .map(|commitment| commitment.bitfield::<F, BOARD_SIZE>())
            .collect::<Vec<[F; BOARD_SIZE]>>()
            .try_into()
            .unwrap()
    }

    /**
     * Render ASCII to the console representing the ship placement
     */
    pub fn print(&self) {
        let mut lines = Vec::<String>::new();
        for i in 0..BOARD_SIZE {
            if i % 10 == 0 {
                let mut out = format!("{} |", i / 10);
                for j in 0..10 {
                    out = format!("{} {}", out, self.state.value[i + j] as u8);
                }
                lines.push(out);
            }
        }
        lines.push(String::from(" (Y)"));
        lines.reverse();
        lines.push(String::from("   -------------------- (X)"));
        lines.push(String::from("    0 1 2 3 4 5 6 7 8 9"));
        for line in lines {
            println!("{}", line);
        }
    }
}

// State mutation utilities
impl Board {
    /**
     * Place a ship down on the board
     *
     * @param self - the board to place a ship on
     * @param ship - the type of ship to place
     * @return - Ok, or a string explaining why the placement failed
     */
    pub fn place(&mut self, ship: Ship) -> Result<(), &'static str> {
        // let x = ship as u8;
        if self.ships[ship.ship_type].is_some() {
            Err("Ship type has already been placed!")
        } else if self.check_collisions(ship) {
            Err("Ship collides with a previously placed ship!")
        } else {
            // add ship to deck
            self.ships.add(ship);
            // place ship on board
            let coordinates = ship.coordinates(false);
            for coordinate in coordinates {
                self.state.value.get_mut(coordinate).unwrap().set(true);
            }
            Ok(())
        }
    }
}

// needed functionality for malicious inputs
// make a ship commitment where ship length = Z = X + Y where bits are set in X + Y so they transpose as in order but are separate commitments
// make a ship commitment where bits are not in order
// make a ship commitmnet

// impl
#[cfg(test)]
mod test {

    use super::*;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3, Spec};
    use halo2_proofs::pasta::Fp;

    // #[test]
    // fn test() {
    //     let board = Board::from(&Deck::default());
    //     // board.print();
    //     // hash([Fp::from(self.state.into_inner())])
    //     let witness = board.private_witness();
    //     println!("Hash: {:?}", witness.0);
    // }

    #[test]
    fn test2() {
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        board.print();
        // get commitment bits
        let bits = [
            board.ships.carrier.unwrap().bits(false),
            board.ships.battleship.unwrap().bits(false),
            board.ships.cruiser.unwrap().bits(false),
            board.ships.submarine.unwrap().bits(false),
            board.ships.destroyer.unwrap().bits(false),
        ];
        println!("Transposed assignments\n------------------------");
        println!("    C B R S D");
        for i in 0..BOARD_SIZE {
            let mut row = format!("{}|", i);
            if i / 10 == 0 {
                row = format!(" {}", row)
            };
            for j in 0..bits.len() {
                row = format!("{} {}", row, bits[j].value[i] as u8)
            }
            println!("{}", row);
        }

        let bits = [
            board.ships.carrier.unwrap().bits(true),
            board.ships.battleship.unwrap().bits(true),
            board.ships.cruiser.unwrap().bits(true),
            board.ships.submarine.unwrap().bits(true),
            board.ships.destroyer.unwrap().bits(true),
        ];
        println!("Untransposed assignments\n------------------------");
        println!("    C B R S D");
        for i in 0..BOARD_SIZE {
            let mut row = format!("{}|", i);
            if i / 10 == 0 {
                row = format!(" {}", row)
            };
            for j in 0..bits.len() {
                row = format!("{} {}", row, bits[j].value[i] as u8)
            }
            println!("{}", row);
        }
    }
}
