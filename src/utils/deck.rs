use {
    crate::utils::ship::{Ship, ShipType},
    std::ops::{Index, IndexMut},
};

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
