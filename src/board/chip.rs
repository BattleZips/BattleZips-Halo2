use {
    crate::{
        bitify::bitify::{BitifyConfig, Num2BitsChip},
        board::gadget::{BoardGadget, Commitments, Placements},
        placement::{
            chip::{PlacementChip, PlacementConfig},
            primitives::PlacementBits,
        },
        transpose::chip::{TransposeChip, TransposeConfig},
        utils::{
            board::{Deck, BOARD_SIZE},
            ship::ShipType,
        },
    },
    halo2_gadgets::poseidon::{Pow5Chip, Pow5Config},
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{AssignedCell, Chip, Layouter, Region, Value},
        plonk::{
            Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Selector,
        },
        poly::Rotation,
    },
    std::marker::PhantomData,
};

// bundles all placement configs together
#[derive(Clone, Copy, Debug)]
pub struct PlacementConfigs<F: FieldExt> {
    carrier: PlacementConfig<F, 5>,
    battleship: PlacementConfig<F, 4>,
    cruiser: PlacementConfig<F, 3>,
    submarine: PlacementConfig<F, 3>,
    destroyer: PlacementConfig<F, 2>,
}

/**
 * Contains all storage needed to verify a battleship board
 */
#[derive(Clone, Debug)]
pub struct BoardConfig<F: FieldExt> {
    pub num2bits: [BitifyConfig; 10],
    pub placement: PlacementConfigs<F>,
    pub transpose: TransposeConfig<F>,
    pub advice: [Column<Advice>; 11],
    pub fixed: [Column<Fixed>; 1],
    pub selectors: [Selector; 1],
    _marker: PhantomData<F>,
}

/**
 * Circuit for proving a valid battleship board configuration
 *    * prove 5 types of ships placed correctly
 *    * prove public commitment is the signed poseidon hash of board integer
 */
pub struct BoardChip<F: FieldExt> {
    config: BoardConfig<F>,
}

impl<F: FieldExt> Chip<F> for BoardChip<F> {
    type Config = BoardConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/**
 * Instructions used by the board chip
 */
pub trait BoardInstructions<F: FieldExt> {
    /**
     * Load the 10 ship placement commitments + transposed commitment into the advice column
     *
     * @param gadget - BoardGadget holding board util object
     * @return - tuple of references to ship commitments ([0..10]), board commitment ([10])
     */
    fn load_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
    ) -> Result<Commitments<F>, Error>;

    /**
     * Load each commitment into a bits2num chip to get constrained 100 bit decompositions
     *
     * @param gadget - BoardGadget functionality
     * @param commitments - assigned cells of commitments
     */
    fn decompose_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
        commitment: &Commitments<F>,
    ) -> Result<Placements<F>, Error>;

    /**
     * Load decomposed bits into placement chips
     *
     * @param ships - deck of ship placements
     * @param placements - references to all assigned cells for bits2num decompositions
     * @return - Ok if placements were valid, and Errors otherwise
     */
    fn synth_placements(
        &self,
        layouter: &mut impl Layouter<F>,
        ships: Deck,
        placements: Placements<F>,
    ) -> Result<(), Error>;

    /**
     * Transpose ship placement bit decompositions into a single board and recompose into a single commitment
     *
     * @param gadget - board gadget
     * @param placements - reference to assigned cells of bits2num decomposed ship commitments
     * @return - reference to transposed binary decomposition representing board commitment
     */
    fn transpose_placements(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
        placements: Placements<F>,
    ) -> Result<PlacementBits<F>, Error>;
}

impl<F: FieldExt> BoardChip<F> {
    pub fn new(config: BoardConfig<F>) -> Self {
        BoardChip { config }
    }

    /**
     * Configure the computation space of the circuit & return BoardConfig
     */
    pub fn configure(meta: &mut ConstraintSystem<F>) -> BoardConfig<F> {
        // define advice
        let mut advice = Vec::<Column<Advice>>::new();
        for _ in 0..11 {
            let col = meta.advice_column();
            meta.enable_equality(col);
            advice.push(col);
        }
        let advice: [Column<Advice>; 11] = advice.try_into().unwrap();

        // define fixed
        let mut fixed = Vec::<Column<Fixed>>::new();
        for _ in 0..1 {
            let col = meta.fixed_column();
            meta.enable_constant(col);
            fixed.push(col);
        }
        let fixed: [Column<Fixed>; 1] = fixed.try_into().unwrap();

        // define selectors
        let mut selectors = Vec::<Selector>::new();
        for _ in 0..1 {
            selectors.push(meta.selector());
        }
        let selectors: [Selector; 1] = selectors.try_into().unwrap();

        // define bits2num chips
        let mut num2bits = Vec::<BitifyConfig>::new();
        for _ in 0..10 {
            num2bits.push(Num2BitsChip::<_, BOARD_SIZE>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ));
        }
        let num2bits: [BitifyConfig; 10] = num2bits.try_into().unwrap();

        // define placement chips
        let placement = PlacementConfigs {
            carrier: PlacementChip::<F, 5>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ),
            battleship: PlacementChip::<F, 4>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ),
            cruiser: PlacementChip::<F, 3>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ),
            submarine: PlacementChip::<F, 3>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ),
            destroyer: PlacementChip::<F, 2>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ),
        };

        // define transpose chip
        let transpose =
            TransposeChip::<F>::configure(meta, advice[0..10].try_into().unwrap(), advice[10]);

        // define poseidon chip
        // let poseidon = Pow5Chip::<F, 3, 2>::config(meta, state, partial_sbox, rc_a, rc_b)

        // define gates
        meta.create_gate("Commitment orientation H OR V == 0 constraint", |meta| {
            let mut commitments = Vec::<Expression<F>>::new();
            for i in 0..10 {
                commitments.push(meta.query_advice(advice[i], Rotation::cur()));
            }
            let selector = meta.query_selector(selectors[0]);
            Constraints::with_selector(
                selector,
                [
                    (
                        "Aircraft Carrier H OR V == 0",
                        commitments[0].clone() * commitments[1].clone(),
                    ),
                    (
                        "Battleship H OR V == 0",
                        commitments[2].clone() * commitments[3].clone(),
                    ),
                    (
                        "Cruiser H OR V == 0",
                        commitments[4].clone() * commitments[5].clone(),
                    ),
                    (
                        "Submarine H OR V == 0",
                        commitments[6].clone() * commitments[7].clone(),
                    ),
                    (
                        "Destroyer H OR V == 0",
                        commitments[8].clone() * commitments[9].clone(),
                    ),
                ],
            )
        });

        // return config
        BoardConfig {
            num2bits,
            placement,
            transpose,
            advice,
            fixed,
            selectors,
            _marker: PhantomData,
        }
    }

    /**
     * Synthesize a proof of a valid board
     *
     * @param gadget - helper
     */
    pub fn synthesize(
        &self,
        mut layouter: impl Layouter<F>,
        gadget: BoardGadget<F>,
    ) -> Result<(), Error> {
        let commitments = self.load_commitments(&mut layouter, gadget)?;
        let placements = self.decompose_commitments(&mut layouter, gadget, &commitments)?;
        self.synth_placements(&mut layouter, gadget.board.ships, placements.clone())?;
        let transposed = self.transpose_placements(&mut layouter, gadget, placements.clone())?;
        Ok(())
    }
}

impl<F: FieldExt> BoardInstructions<F> for BoardChip<F> {
    fn load_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
    ) -> Result<Commitments<F>, Error> {
        let assigned: [AssignedCell<F, F>; 10] = layouter.assign_region(
            || "load ship placements",
            |mut region: Region<F>| {
                // assign ship commitments
                let ship_commitments = gadget.private_witness();
                let mut cells = Vec::<AssignedCell<F, F>>::new();
                for i in 0..10 {
                    let label = BoardGadget::<F>::commitment_label(i);
                    cells.push(region.assign_advice(
                        || format!("{} ship commitment", label),
                        self.config.advice[i],
                        0,
                        || Value::known(ship_commitments[i]),
                    )?);
                }
                _ = self.config.selectors[0].enable(&mut region, 0);
                Ok(cells.try_into().unwrap())
            },
        )?;
        Ok(assigned)
    }

    fn decompose_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
        commitments: &Commitments<F>,
    ) -> Result<Placements<F>, Error> {
        let bits = gadget.decompose_bits();
        let mut placements = Vec::<PlacementBits<F>>::new();
        for i in 0..10 {
            let num2bits = Num2BitsChip::<F, BOARD_SIZE>::new(commitments[i].clone(), bits[i]);
            let label = BoardGadget::<F>::commitment_label(i);
            let assigned_bits = num2bits.synthesize(
                self.config.num2bits[i],
                layouter.namespace(|| format!("{} bits2num", label)),
            )?;
            placements.push(PlacementBits::<F>::from(assigned_bits));
        }
        Ok(placements.try_into().unwrap())
    }

    fn synth_placements(
        &self,
        layouter: &mut impl Layouter<F>,
        ships: Deck,
        placements: Placements<F>,
    ) -> Result<(), Error> {
        PlacementChip::<F, 5>::new(self.config.placement.carrier).synthesize(
            layouter,
            ships.carrier.unwrap(),
            placements[0].clone(),
            placements[1].clone(),
        )?;
        PlacementChip::<F, 4>::new(self.config.placement.battleship).synthesize(
            layouter,
            ships.battleship.unwrap(),
            placements[2].clone(),
            placements[3].clone(),
        )?;
        PlacementChip::<F, 3>::new(self.config.placement.cruiser).synthesize(
            layouter,
            ships.cruiser.unwrap(),
            placements[4].clone(),
            placements[5].clone(),
        )?;
        PlacementChip::<F, 3>::new(self.config.placement.submarine).synthesize(
            layouter,
            ships.submarine.unwrap(),
            placements[6].clone(),
            placements[7].clone(),
        )?;
        PlacementChip::<F, 2>::new(self.config.placement.destroyer).synthesize(
            layouter,
            ships.destroyer.unwrap(),
            placements[8].clone(),
            placements[9].clone(),
        )?;
        Ok(())
    }

    fn transpose_placements(
        &self,
        layouter: &mut impl Layouter<F>,
        gadget: BoardGadget<F>,
        placements: Placements<F>,
    ) -> Result<PlacementBits<F>, Error> {
        let chip = TransposeChip::<F>::new(self.config.transpose);
        let bits = gadget.board.state.bitfield::<F, BOARD_SIZE>();
        let commitment = F::from_u128(gadget.board.state.lower_u128());
        Ok(chip
            .synthesize(layouter, commitment, bits, placements)
            .unwrap())
    }
}
