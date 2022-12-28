use {
    crate::{
        bitify::bitify::{BitifyConfig, Bits2NumChip, Num2BitsChip},
        placement::{
            chip::{PlacementChip, PlacementConfig},
            primitives::AssignedBits,
        },
        transpose::chip::{TransposeChip, TransposeConfig},
        utils::{
            binary::BinaryValue,
            board::{Board, Deck, BOARD_SIZE},
            ship::{get_ship_length, get_ship_name},
        },
    },
    halo2_gadgets::poseidon::{
        primitives::{ConstantLength, Spec},
        Hash, Pow5Chip, Pow5Config,
    },
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{AssignedCell, Chip, Layouter, Region, Value},
        plonk::{
            Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance,
            Selector,
        },
        poly::Rotation,
    },
    std::marker::PhantomData,
};

pub type Commitments<F> = [AssignedCell<F, F>; 10];
pub type Placements<F> = [AssignedBits<F>; 10];

/**
 * Return a label for commitments in debugging
 *
 * @param i - the enumerable index [0-9] of commitment types
 * @return - the label to be used in debugging messages
 */
pub fn commitment_label(i: usize) -> String {
    String::from(match i {
        0 => "H5",
        1 => "V5",
        2 => "H4",
        3 => "V4",
        4 => "H3a",
        5 => "V3a",
        6 => "H3b",
        7 => "V3b",
        8 => "H2",
        9 => "V2",
        _other => "NULL",
    })
}

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
    pub bits2num: BitifyConfig,
    pub placement: PlacementConfigs<F>,
    pub transpose: TransposeConfig<F>,
    pub poseidon: Pow5Config<F, 3, 2>,
    pub advice: [Column<Advice>; 11],
    pub fixed: [Column<Fixed>; 6],
    pub instance: Column<Instance>,
    pub selectors: [Selector; 1],
    _marker: PhantomData<F>,
}

/**
 * Circuit for proving a valid battleship board configuration
 *    * prove 5 types of ships placed correctly
 *    * prove public commitment is the signed poseidon hash of board integer
 */
pub struct BoardChip<S: Spec<F, 3, 2>, F: FieldExt> {
    config: BoardConfig<F>,
    _marker: PhantomData<S>,
}

impl<S: Spec<F, 3, 2>, F: FieldExt> Chip<F> for BoardChip<S, F> {
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
pub trait BoardInstructions<S: Spec<F, 3, 2>, F: FieldExt> {
    /**
     * Load the 10 ship placement commitments
     *
     * @param ship_commitments - array of 10 BinaryValues - H and V commitments for each ship
     * @return - array of 10 AssignedCells storing ship commitments in chip
     */
    fn load_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        ship_commitments: [BinaryValue; 10],
    ) -> Result<Commitments<F>, Error>;

    /**
     * Load each commitment into a num2bits chip to get constrained 100 bit decompositions
     *
     * @param board - board object storing state + commmitment decompose functionality
     * @param commitments - assigned cells of commitments
     */
    fn decompose_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        ship_commitments: [BinaryValue; 10],
        commitment: [AssignedCell<F, F>; 10],
    ) -> Result<Placements<F>, Error>;

    /**
     * Load decomposed bits into placement chips
     *
     * @param ships - the chosen BinaryValue ship_commitment for a H, V pair to use
     * @param placements - references to all assigned cells for num2bits decompositions
     * @return - Ok if placements were valid, and Errors otherwise
     */
    fn synth_placements(
        &self,
        layouter: &mut impl Layouter<F>,
        ships: [BinaryValue; 5],
        placements: Placements<F>,
    ) -> Result<(), Error>;

    /**
     * Transpose ship placement bit decompositions into a single board and recompose into a single commitment
     *
     * @param board - binary value encoded with board state (all transposed ships)
     * @param placements - reference to assigned cells of num2bits decomposed ship commitments
     * @return - reference to transposed binary decomposition representing board commitment
     */
    fn transpose_placements(
        &self,
        layouter: &mut impl Layouter<F>,
        board: BinaryValue,
        placements: Placements<F>,
    ) -> Result<AssignedBits<F>, Error>;

    /**
     * Recompose the bits from the board transposition instruciton into a single element
     *
     * @param board -  binary value encoded with board state (all transposed ships)
     * @param transposed - reference to assigned cells storing bits that represent serialized board state
     * @return - if successful, return the binary composition in little endian order of the transposed bits
     */
    fn recompose_board(
        &self,
        layouter: &mut impl Layouter<F>,
        board: BinaryValue,
        transposed: [AssignedCell<F, F>; BOARD_SIZE],
    ) -> Result<AssignedCell<F, F>, Error>;

    /**
     * Constrained computation of poseidon hash of transposed board state
     *
     * @param preimage - assigned cell storing the transposed board state to hash
     * @return - if successful, assigned cell storing the poseidon hash of the board state
     */
    fn hash_board(
        &self,
        layouter: &mut impl Layouter<F>,
        preimage: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

impl<S: Spec<F, 3, 2>, F: FieldExt> BoardChip<S, F> {
    pub fn new(config: BoardConfig<F>) -> Self {
        BoardChip {
            config,
            _marker: PhantomData,
        }
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
        for _ in 0..6 {
            fixed.push(meta.fixed_column());
        }
        let fixed: [Column<Fixed>; 6] = fixed.try_into().unwrap();
        meta.enable_constant(fixed[0]);

        // define instance column
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // define selectors
        let mut selectors = Vec::<Selector>::new();
        for _ in 0..1 {
            selectors.push(meta.selector());
        }
        let selectors: [Selector; 1] = selectors.try_into().unwrap();

        // define num2bits chips
        let mut num2bits = Vec::<BitifyConfig>::new();
        for _ in 0..10 {
            num2bits.push(Num2BitsChip::<_, BOARD_SIZE>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ));
        }
        let num2bits: [BitifyConfig; 10] = num2bits.try_into().unwrap();

        // define bits2num chip
        let bits2num = Bits2NumChip::<_, BOARD_SIZE>::configure(
            meta, advice[0], advice[1], advice[2], fixed[0],
        );

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
        let poseidon = Pow5Chip::<F, 3, 2>::configure::<S>(
            meta,
            [advice[0], advice[1], advice[2]],
            advice[3],
            [fixed[3], fixed[4], fixed[5]],
            [fixed[0], fixed[1], fixed[2]], // flipped so fixed[0] is constant
        );

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
            bits2num,
            placement,
            transpose,
            poseidon,
            advice,
            fixed,
            instance,
            selectors,
            _marker: PhantomData,
        }
    }

    /**
     * Synthesize a proof of a valid board
     *
     * @param ship_commitments - 10x private ship commitments indicating a horizontal or vertical placement
     * @param board - board state as a BinaryValue
     */
    pub fn synthesize(
        &self,
        mut layouter: impl Layouter<F>,
        ship_commitments: [BinaryValue; 10],
        board: BinaryValue,
    ) -> Result<(), Error> {
        // compute combined ship commitments
        let mut ships = Vec::<BinaryValue>::new();
        for i in 0..5 {
            ships.push(ship_commitments[i * 2].zip(ship_commitments[i * 2 + 1]));
        }
        let ships: [BinaryValue; 5] = ships.try_into().unwrap();
        // load ship commitments into advice
        let assigned_commitments = self.load_commitments(&mut layouter, ship_commitments)?;
        // decompose commitments into 100 bits each
        let placements =
            self.decompose_commitments(&mut layouter, ship_commitments, assigned_commitments)?;
        // run individual ship placement rule checks
        self.synth_placements(&mut layouter, ships, placements.clone())?;
        // check that ships can all be placed together to form a valid board
        let transposed_bits =
            self.transpose_placements(&mut layouter, board, placements.clone())?;
        // recompose the 100 bit board state into a single value
        let transposed = self.recompose_board(&mut layouter, board, transposed_bits)?;
        // hash the board state into public commitment
        // @todo: add signing here to prevent known ciphertext attack
        let commitment = self.hash_board(&mut layouter, transposed.clone())?;
        // export constained board commitment to public instance column
        layouter.constrain_instance(commitment.cell(), self.config.instance, 0)?;
        Ok(())
    }
}

impl<S: Spec<F, 3, 2>, F: FieldExt> BoardInstructions<S, F> for BoardChip<S, F> {
    fn load_commitments(
        &self,
        layouter: &mut impl Layouter<F>,
        ship_commitments: [BinaryValue; 10],
    ) -> Result<Commitments<F>, Error> {
        let assigned: [AssignedCell<F, F>; 10] = layouter.assign_region(
            || "load ship placements",
            |mut region: Region<F>| {
                // assign ship commitments
                let mut cells = Vec::<AssignedCell<F, F>>::new();
                for i in 0..10 {
                    let label = commitment_label(i);
                    cells.push(region.assign_advice(
                        || format!("{} ship commitment", label),
                        self.config.advice[i],
                        0,
                        || Value::known(F::from_u128(ship_commitments[i].lower_u128())),
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
        ship_commitments: [BinaryValue; 10],
        assigned_commitments: [AssignedCell<F, F>; 10],
    ) -> Result<Placements<F>, Error> {
        let mut placements = Vec::<AssignedBits<F>>::new();
        for i in 0..10 {
            let bits = ship_commitments[i].bitfield::<F, BOARD_SIZE>();
            let num2bits =
                Num2BitsChip::<F, BOARD_SIZE>::new(assigned_commitments[i].clone(), bits);
            let label = commitment_label(i);
            let assigned_bits = num2bits.synthesize(
                self.config.num2bits[i],
                layouter.namespace(|| format!("{} num2bits", label)),
            )?;
            placements.push(AssignedBits::<F>::from(assigned_bits));
        }
        Ok(placements.try_into().unwrap())
    }

    fn synth_placements(
        &self,
        layouter: &mut impl Layouter<F>,
        ships: [BinaryValue; 5],
        placements: Placements<F>,
    ) -> Result<(), Error> {
        PlacementChip::<F, 5>::new(self.config.placement.carrier).synthesize(
            layouter,
            ships[0],
            placements[0].clone(),
            placements[1].clone(),
        )?;
        PlacementChip::<F, 4>::new(self.config.placement.battleship).synthesize(
            layouter,
            ships[1],
            placements[2].clone(),
            placements[3].clone(),
        )?;
        PlacementChip::<F, 3>::new(self.config.placement.cruiser).synthesize(
            layouter,
            ships[2],
            placements[4].clone(),
            placements[5].clone(),
        )?;
        PlacementChip::<F, 3>::new(self.config.placement.submarine).synthesize(
            layouter,
            ships[3],
            placements[6].clone(),
            placements[7].clone(),
        )?;
        PlacementChip::<F, 2>::new(self.config.placement.destroyer).synthesize(
            layouter,
            ships[4],
            placements[8].clone(),
            placements[9].clone(),
        )?;
        Ok(())
    }

    fn transpose_placements(
        &self,
        layouter: &mut impl Layouter<F>,
        board: BinaryValue,
        placements: Placements<F>,
    ) -> Result<AssignedBits<F>, Error> {
        let chip = TransposeChip::<F>::new(self.config.transpose);
        let bits = board.bitfield::<F, BOARD_SIZE>();
        let commitment = F::from_u128(board.lower_u128());
        Ok(chip
            .synthesize(layouter, commitment, bits, placements)
            .unwrap())
    }

    fn recompose_board(
        &self,
        layouter: &mut impl Layouter<F>,
        board: BinaryValue,
        transposed: [AssignedCell<F, F>; BOARD_SIZE],
    ) -> Result<AssignedCell<F, F>, Error> {
        Ok(
            Bits2NumChip::<F, BOARD_SIZE>::new(F::from_u128(board.lower_u128()), transposed)
                .synthesize(
                    self.config.bits2num,
                    layouter.namespace(|| "transposed bits2num"),
                )?,
        )
    }

    fn hash_board(
        &self,
        layouter: &mut impl Layouter<F>,
        preimage: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let chip = Pow5Chip::construct(self.config.poseidon.clone());

        let hasher =
            Hash::<_, _, S, ConstantLength<1>, 3, 2>::init(chip, layouter.namespace(|| "hasher"))?;
        hasher.hash(layouter.namespace(|| "hash"), [preimage])
    }
}
