use {
    crate::{
        chips::{
            bitify::{BitifyConfig, Bits2NumChip, Num2BitsChip},
            pedersen::{PedersenCommitmentChip, PedersenCommitmentConfig},
            placement::{AssignedBits, PlacementChip, PlacementConfig},
            transpose::{TransposeChip, TransposeConfig},
        },
        utils::{binary::BinaryValue, board::BOARD_SIZE, pedersen::pedersen_commit},
    },
    halo2_proofs::{
        arithmetic::{FieldExt, CurveAffine},
        circuit::{AssignedCell, Chip, Layouter, Region, Value},
        pasta::{pallas, group::Curve},
        plonk::{
            Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Instance,
            Selector, TableColumn,
        },
        poly::Rotation,
    },
};

pub type Commitments = [AssignedCell<pallas::Base, pallas::Base>; 10];
pub type Placements = [AssignedBits<pallas::Base>; 10];

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
pub struct PlacementConfigs {
    carrier: PlacementConfig<pallas::Base, 5>,
    battleship: PlacementConfig<pallas::Base, 4>,
    cruiser: PlacementConfig<pallas::Base, 3>,
    submarine: PlacementConfig<pallas::Base, 3>,
    destroyer: PlacementConfig<pallas::Base, 2>,
}

/**
 * Contains all storage needed to verify a battleship board
 */
#[derive(Clone, Debug)]
pub struct BoardConfig {
    // chip configs
    pub num2bits: [BitifyConfig; 10],
    pub bits2num: BitifyConfig,
    pub placement: PlacementConfigs,
    pub transpose: TransposeConfig<pallas::Base>,
    pub pedersen: PedersenCommitmentConfig,
    // columns
    pub advice: [Column<Advice>; 11],
    pub fixed: [Column<Fixed>; 8],
    pub table_idx: TableColumn,
    pub instance: Column<Instance>,
    // selectors
    pub selectors: [Selector; 1],
}

/**
 * Circuit for proving a valid battleship board configuration
 *    * prove 5 types of ships placed correctly
 *    * prove public commitment is the signed poseidon hash of board integer
 */
pub struct BoardChip {
    config: BoardConfig,
}

impl Chip<pallas::Base> for BoardChip {
    type Config = BoardConfig;
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
pub trait BoardInstructions {
    /**
     * Load the 10 ship placement commitments
     *
     * @param ship_commitments - array of 10 BinaryValues - H and V commitments for each ship
     * @return - array of 10 AssignedCells storing ship commitments in chip
     */
    fn load_commitments(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        ship_commitments: &[BinaryValue; 10],
    ) -> Result<Commitments, Error>;

    /**
     * Load each commitment into a num2bits chip to get constrained 100 bit decompositions
     *
     * @param board - board object storing state + commmitment decompose functionality
     * @param commitments - assigned cells of commitments
     */
    fn decompose_commitments(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        ship_commitments: &[BinaryValue; 10],
        commitment: &[AssignedCell<pallas::Base, pallas::Base>; 10],
    ) -> Result<Placements, Error>;

    /**
     * Load decomposed bits into placement chips
     *
     * @param ships - the chosen BinaryValue ship_commitment for a H, V pair to use
     * @param placements - references to all assigned cells for num2bits decompositions
     * @return - Ok if placements were valid, and Errors otherwise
     */
    fn synth_placements(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        ships: &[BinaryValue; 5],
        placements: &Placements,
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
        layouter: &mut impl Layouter<pallas::Base>,
        board: &BinaryValue,
        placements: &Placements,
    ) -> Result<AssignedBits<pallas::Base>, Error>;

    /**
     * Recompose the bits from the board transposition instruciton into a single element
     *
     * @param board -  binary value encoded with board state (all transposed ships)
     * @param transposed - reference to assigned cells storing bits that represent serialized board state
     * @return - if successful, return the binary composition in little endian order of the transposed bits
     */
    fn recompose_board(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        board: &BinaryValue,
        transposed: &[AssignedCell<pallas::Base, pallas::Base>; BOARD_SIZE],
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error>;

    /**
     * Compute the pedersen commitment to the board state
     *
     * @param board_state - base field element that can be decomposed into board state
     * @param board_commitment_trapdoor - scalar field element used to blind the commitment
     * @return - assigned cell storing the (x, y) coordinates of commitment on pallas curve
     */
    fn commit_board(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        board_state: &AssignedCell<pallas::Base, pallas::Base>,
        board_commitment_trapdoor: &pallas::Scalar,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 2], Error>;
}

impl BoardChip {
    pub fn new(config: BoardConfig) -> Self {
        BoardChip { config }
    }

    /**
     * Configure the computation space of the circuit & return BoardConfig
     */
    pub fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> BoardConfig {
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
        for _ in 0..8 {
            fixed.push(meta.fixed_column());
        }
        let fixed: [Column<Fixed>; 8] = fixed.try_into().unwrap();
        meta.enable_constant(fixed[0]);

        // define table column
        let table_idx = meta.lookup_table_column();

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
            carrier: PlacementChip::<pallas::Base, 5>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ),
            battleship: PlacementChip::<pallas::Base, 4>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ),
            cruiser: PlacementChip::<pallas::Base, 3>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ),
            submarine: PlacementChip::<pallas::Base, 3>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ),
            destroyer: PlacementChip::<pallas::Base, 2>::configure(
                meta, advice[0], advice[1], advice[2], fixed[0],
            ),
        };

        // define transpose chip
        let transpose = TransposeChip::<pallas::Base>::configure(
            meta,
            advice[0..10].try_into().unwrap(),
            advice[10],
        );

        // define pedersen chip
        let pedersen = PedersenCommitmentChip::configure(
            meta,
            advice[0..10].try_into().unwrap(),
            fixed,
            table_idx,
        );

        // define gates
        meta.create_gate("Commitment orientation H OR V == 0 constraint", |meta| {
            let mut commitments = Vec::<Expression<pallas::Base>>::new();
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
            pedersen,
            advice,
            fixed,
            table_idx,
            instance,
            selectors,
        }
    }

    /**
     * Synthesize a proof of a valid board
     *
     * @param ship_commitments - 10x private ship commitments indicating a horizontal or vertical placement
     * @param board - board state as a BinaryValue
     * @param board_commitment_trapdoor - the trapdoor for the board commitment
     * @return - Ok if the proof synthesizes successfully
     */
    pub fn synthesize(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        ship_commitments: [BinaryValue; 10],
        board: BinaryValue,
        board_commitment_trapdoor: pallas::Scalar,
    ) -> Result<(), Error> {
        // compute combined ship commitments
        let mut ships = Vec::<BinaryValue>::new();
        for i in 0..5 {
            ships.push(ship_commitments[i * 2].zip(ship_commitments[i * 2 + 1]));
        }
        let ships: [BinaryValue; 5] = ships.try_into().unwrap();
        // load ship commitments into advice
        let assigned_commitments = self.load_commitments(&mut layouter, &ship_commitments)?;
        // decompose commitments into 100 bits each
        let placements =
            self.decompose_commitments(&mut layouter, &ship_commitments, &assigned_commitments)?;
        // run individual ship placement rule checks
        self.synth_placements(&mut layouter, &ships, &placements)?;
        // check that ships can all be placed together to form a valid board
        let transposed_bits =
            self.transpose_placements(&mut layouter, &board, &placements)?;
        // recompose the 100 bit board state into a single value
        let transposed = self.recompose_board(&mut layouter, &board, &transposed_bits)?;
        // synthesize pedersen commitment to board state
        let commitment =
            self.commit_board(&mut layouter, &transposed, &board_commitment_trapdoor)?;
        // // compute the pedersen commitment to publicly attest to
        // let commitment_values = {
        //     let board_state = pallas::Base::from_u128(board.lower_u128());
        //     let commitment = pedersen_commit(&board_state, &board_commitment_trapdoor).to_affine();
        //     let x = commitment.clone().coordinates().unwrap().x().to_owned();
        //     let y = commitment.clone().coordinates().unwrap().y().to_owned();
        //     [x, y]
        // };
        // export constained board commitment to public instance column
        layouter.constrain_instance(commitment[0].cell(), self.config.instance, 0)?;
        layouter.constrain_instance(commitment[1].cell(), self.config.instance, 0)?;

        Ok(())
    }
}

impl BoardInstructions for BoardChip {
    fn load_commitments(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        ship_commitments: &[BinaryValue; 10],
    ) -> Result<Commitments, Error> {
        let assigned: [AssignedCell<pallas::Base, pallas::Base>; 10] = layouter.assign_region(
            || "load ship placements",
            |mut region: Region<pallas::Base>| {
                // assign ship commitments
                let mut cells = Vec::<AssignedCell<pallas::Base, pallas::Base>>::new();
                for i in 0..10 {
                    let label = commitment_label(i);
                    cells.push(region.assign_advice(
                        || format!("{} ship commitment", label),
                        self.config.advice[i],
                        0,
                        || Value::known(pallas::Base::from_u128(ship_commitments[i].lower_u128())),
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
        layouter: &mut impl Layouter<pallas::Base>,
        ship_commitments: &[BinaryValue; 10],
        assigned_commitments: &[AssignedCell<pallas::Base, pallas::Base>; 10],
    ) -> Result<Placements, Error> {
        let mut placements = Vec::<AssignedBits<pallas::Base>>::new();
        for i in 0..10 {
            let bits = ship_commitments[i].bitfield::<pallas::Base, BOARD_SIZE>();
            let num2bits = Num2BitsChip::<pallas::Base, BOARD_SIZE>::new(
                assigned_commitments[i].clone(),
                bits,
            );
            let label = commitment_label(i);
            let assigned_bits = num2bits.synthesize(
                self.config.num2bits[i],
                layouter.namespace(|| format!("{} num2bits", label)),
            )?;
            placements.push(AssignedBits::<pallas::Base>::from(assigned_bits));
        }
        Ok(placements.try_into().unwrap())
    }

    fn synth_placements(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        ships: &[BinaryValue; 5],
        placements: &Placements,
    ) -> Result<(), Error> {
        PlacementChip::<pallas::Base, 5>::new(self.config.placement.carrier).synthesize(
            layouter,
            &ships[0],
            &placements[0],
            &placements[1],
        )?;
        PlacementChip::<pallas::Base, 4>::new(self.config.placement.battleship).synthesize(
            layouter,
            &ships[1],
            &placements[2],
            &placements[3],
        )?;
        PlacementChip::<pallas::Base, 3>::new(self.config.placement.cruiser).synthesize(
            layouter,
            &ships[2],
            &placements[4],
            &placements[5],
        )?;
        PlacementChip::<pallas::Base, 3>::new(self.config.placement.submarine).synthesize(
            layouter,
            &ships[3],
            &placements[6],
            &placements[7],
        )?;
        PlacementChip::<pallas::Base, 2>::new(self.config.placement.destroyer).synthesize(
            layouter,
            &ships[4],
            &placements[8],
            &placements[9],
        )?;
        Ok(())
    }

    fn transpose_placements(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        board: &BinaryValue,
        placements: &Placements,
    ) -> Result<AssignedBits<pallas::Base>, Error> {
        let chip = TransposeChip::<pallas::Base>::new(self.config.transpose);
        let bits = board.bitfield::<pallas::Base, BOARD_SIZE>();
        Ok(chip.synthesize(layouter, &bits, placements).unwrap())
    }

    fn recompose_board(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        board: &BinaryValue,
        transposed: &[AssignedCell<pallas::Base, pallas::Base>; BOARD_SIZE],
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        Ok(Bits2NumChip::<pallas::Base, BOARD_SIZE>::new(
            pallas::Base::from_u128(board.lower_u128()),
            transposed,
        )
        .synthesize(
            self.config.bits2num,
            layouter.namespace(|| "transposed bits2num"),
        )?)
    }

    fn commit_board(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        board_state: &AssignedCell<pallas::Base, pallas::Base>,
        board_commitment_trapdoor: &pallas::Scalar,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 2], Error> {
        let chip = PedersenCommitmentChip::new(self.config.pedersen.clone());
        let commitment = chip.synthesize(
            layouter.namespace(|| "pedersen"),
            &board_state,
            Value::known(board_commitment_trapdoor.clone()),
        )?;
        // return pedersen commitment points
        Ok([
            commitment.clone().inner().x(),
            commitment.clone().inner().y(),
        ])
    }
}
