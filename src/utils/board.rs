use {
    crate::{
        utils::{
            // ship::{Ship, ShipLength, ShipPlacement},
        },
        board::gadget::PrivateInput,
    },
    bitvec::prelude::*,
    halo2_gadgets::poseidon::{
        primitives::{Hash, ConstantLength, P128Pow5T3, Spec},
    },
    std::ops::{Index, IndexMut}
};

pub const BOARD_SIZE: usize = 100;

// contains all 5 ship commitments
// #[derive(Clone, Copy, Debug)]
// pub struct Deck {
//     pub carrier: Option<ShipPlacement<{ ShipLength::CARRIER }>>,
//     pub battleship: Option<ShipPlacement<{ ShipLength::BATTLESHIP }>>,
//     pub cruiser: Option<ShipPlacement<{ ShipLength::CRUISER }>>,
//     pub submarine: Option<ShipPlacement<{ ShipLength::SUBMARINE }>>,
//     pub destroyer: Option<ShipPlacement<{ ShipLength::DESTROYER }>>,
// }

// impl Deck {
//     /**
//      * Return an empty deck
//      * 
//      * @return - Board where commitment = 0 and all deck options are None
//      */
//     fn new() -> Self {
//         Deck {
//             carrier: None(),
//             battleship: None(),
//             cruiser: None(),
//             submarine: None(),
//             destroyer: None()
//         }
//     }
// }

// impl Index<Ship> for Deck {
//     fn index(&self, i: Ship) -> Option<ShipPlacement<{ usize }>> {
//         match i {
//             Ship::Carrier => &self.carrier,
//             Ship::Battleship => &self.battleship,
//             Ship::Cruiser => &self.cruiser,
            
//         }
//     }
// }

// // Definition of all state data needed to create board commitments
// pub struct Board {
//     pub ships: Deck,
//     pub state: BitArr!(for BOARD_SIZE, in bool, Lsb0)
// }

// impl Board {

//     /**
//      * Build an empty board object and return
//      * 
//      * @return - Board where commitment = 0 and all deck options are None
//      */
//     fn new() -> Self {
//         Board {
//             ships: Deck::new(),
//             state: BitArray::ZERO
//         }
//     }

//     /**
//      * Build a board object and place based on ship assignments in deck
//      * @dev can place in any combination of ships
//      * 
//      * @param deck - optional assignments for each ship
//      * @return - Board where state is generated from assignments in deck input
//      */
//     fn from(deck: &Deck) -> Self {

//     }

//     /**
//      * Place a ship down on the board
//      * 
//      * @param self - the board to place a ship on
//      * @param ship - the type of ship to place
//      * @param x - the horizontal coordinate for ship head
//      * @param y - the vertical coordinate for ship head
//      * @param z - the horizontal/ vertical body selector
//      * @return - Ok, or a string explaining why the placement failed
//      */
//     fn place(self, ship: Ship, x: u8, y: u8, z: u8) -> Result<(), String> {
//         let x = ship as u8;
//         if self.ships.
//     }

//     /**
//      * Remove a placed ship from the board
//      * 
//      * @param self - the board to remove a ship from
//      * @param ship - the type of ship to remove
//      */
//     fn remove(self, ship: Ship) -> Result<(), String>;
// }
// pub trait BoardUtilities {

//     /

// }

// impl BoardUtilities {

//     fn new() -> Self {

//     }
// }
// // let hashed = Hash::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from(preimage)]);