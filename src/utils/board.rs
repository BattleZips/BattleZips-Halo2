use crate::utils::binary::U256;

use {
    crate::utils::{
        binary::BinaryValue,
        deck::Deck,
        ship::{Ship, WitnessOption, DEFAULT_WITNESS_OPTIONS},
    },
    bitvec::prelude::*,
};

pub const BOARD_SIZE: usize = 100;

// Definition of all state data needed to create board commitments
#[derive(Clone, Copy, Debug)]
pub struct Board {
    pub ships: Deck,
}

// Definition of a deck of ships placed on a board rationally
// Used to generate board/ shot proofs normally (where malicious is used for testing)
impl Board {
    /**
     * Build an empty board object and return
     *
     * @return - Board where commitment = 0 and all ships are unassigned in deck
     */
    pub fn new() -> Self {
        Board { ships: Deck::new() }
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

    // STATE MUTATION UTILITIES //

    /**
     * Place a ship down on the board
     * @dev will fail to proce a correct state summary if ship overlaps with another ship (reflags true bit as true)
     *
     * @param self - the board to place a ship on
     * @param ship - the type of ship to place
     * @return - Ok, or a string explaining why the placement failed
     */
    pub fn place(&mut self, ship: Ship) -> Result<(), &'static str> {
        if self.ships[ship.ship_type].is_some() {
            Err("Ship type has already been placed!")
        } else {
            // add ship to deck
            self.ships.add(ship);
            Ok(())
        }
    }

    // STATE ACCESS UTILITIES //

    /**
     * Compute the private board state as needed for default or test cases
     *
     * @param utilities - Witness utility options for testing malicious cases
     * @return - transposed board state element computed according to witness options
     */
    pub fn state(&self, utilities: [WitnessOption; 5]) -> BinaryValue {
        let mut state = U256::ZERO;
        let ships = self.ships.iterator();
        for i in 0..ships.len() {
            if ships[i].is_some() {
                let ship = ships[i].unwrap();
                let placement = ship.witness(utilities[i]);
                for j in 0..BOARD_SIZE {
                    // transpoe horizontal
                    if placement[0].value[j] {
                        state.get_mut(j).unwrap().set(true);
                    };
                    // transpose horizontal
                    let v_index = j % 10 * 10 + j / 10;
                    if placement[1].value[j] {
                        state.get_mut(v_index).unwrap().set(true);
                    };
                }
            }
        }
        BinaryValue::new(state)
    }

    /**
     * Format the shot commitments as needed for the private witness inputs for a Board proof
     * @dev [H5, V5, H4, V4, H3, V3, H2, V2, H1, V1]
     *
     * @param utilities - Witness utility options for testing malicious cases
     * @return - array of H/V shot commitments values for each ship to witness
     */
    pub fn witness(self, utilities: [WitnessOption; 5]) -> [BinaryValue; 10] {
        let mut full_witness = Vec::<BinaryValue>::new();
        let ships = self.ships.iterator();
        for i in 0..ships.len() {
            let witness = if ships[i].is_none() {
                [BinaryValue::empty(), BinaryValue::empty()]
            } else {
                ships[i].unwrap().witness(utilities[i])
            };
            full_witness.push(witness[0].clone());
            full_witness.push(witness[1].clone());
        }
        full_witness.try_into().unwrap()
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
                    out = format!(
                        "{} {}",
                        out,
                        self.state(DEFAULT_WITNESS_OPTIONS).value[i + j] as u8
                    );
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
