use {
    crate::utils::constants::{
        fixed_bases::{BoardCommitR, BoardCommitV, BoardFixedBases},
        LOOKUP_SIZE,
    },
    halo2_gadgets::{
        ecc::{
            chip::{EccChip, EccConfig},
            EccInstructions, FixedPoint, FixedPointBaseField, Point, ScalarFixed,
        },
        utilities::lookup_range_check::LookupRangeCheckConfig,
    },
    halo2_proofs::{
        circuit::{AssignedCell, Chip, Layouter, Value},
        pasta::{pallas, EpAffine},
        plonk::{Advice, Column, ConstraintSystem, Error, Fixed, TableColumn},
    },
};

#[derive(Clone, Debug)]
pub struct PedersenCommitmentConfig {
    pub table_idx: TableColumn,
    pub ecc: EccConfig<BoardFixedBases>,
}

#[derive(Clone, Debug)]
pub struct PedersenCommitmentChip {
    config: PedersenCommitmentConfig,
}

impl Chip<pallas::Base> for PedersenCommitmentChip {
    type Config = PedersenCommitmentConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl PedersenCommitmentChip {
    pub fn new(config: PedersenCommitmentConfig) -> Self {
        PedersenCommitmentChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advice: [Column<Advice>; 10],
        lagrange: [Column<Fixed>; 8],
        table_idx: TableColumn,
    ) -> PedersenCommitmentConfig {
        // configure range check lookup table chip
        let range_check: LookupRangeCheckConfig<pallas::Base, LOOKUP_SIZE> =
            LookupRangeCheckConfig::configure(meta, advice[9], table_idx);
        // configure ecc chip
        let ecc = EccChip::<BoardFixedBases>::configure(meta, advice, lagrange, range_check);
        // return configuration
        PedersenCommitmentConfig { table_idx, ecc }
    }

    pub fn synthesize(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        value: &AssignedCell<pallas::Base, pallas::Base>,
        trapdoor: Value<pallas::Scalar>,
    ) -> Result<Point<EpAffine, EccChip<BoardFixedBases>>, Error> {
        // load the lookup table
        layouter.assign_table(
            || "table_idx",
            |mut table| {
                // We generate the row values lazily (we only need them during keygen).
                for index in 0..(1 << 10) {
                    table.assign_cell(
                        || "table_idx",
                        self.config.table_idx,
                        index,
                        || Value::known(pallas::Base::from(index as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
        // construct ecc chip
        let ecc_chip = EccChip::construct(self.config.ecc.clone());
        // instantiate commitment trapdoor as a full-width scalar
        let trapdoor = ScalarFixed::new(
            ecc_chip.clone(),
            layouter.namespace(|| "trapdoor"),
            trapdoor,
        )?;
        // synthesize the pedersen commitment computation
        Ok(pedersen_commitment(
            layouter.namespace(|| "pedersen commitment"),
            ecc_chip.clone(),
            value.clone(),
            trapdoor,
        )?)
    }
}

pub fn pedersen_commitment<
    EccChip: EccInstructions<
        pallas::Affine,
        FixedPoints = BoardFixedBases,
        Var = AssignedCell<pallas::Base, pallas::Base>,
    >,
>(
    mut layouter: impl Layouter<pallas::Base>,
    ecc_chip: EccChip,
    // v: FixedPointBaseField<pallas::Affine, EccChip>,
    v: AssignedCell<pallas::Base, pallas::Base>,
    rcv: ScalarFixed<pallas::Affine, EccChip>,
) -> Result<Point<pallas::Affine, EccChip>, Error> {
    // commitment = [v] ValueCommitV
    let commitment = {
        let board_commit_v = FixedPointBaseField::from_inner(ecc_chip.clone(), BoardCommitV);
        board_commit_v.mul(layouter.namespace(|| "[v] BoardCommitV"), v)?
    };

    // blind = [rcv] ValueCommitR
    let (blind, _rcv) = {
        let board_commit_r = BoardCommitR;
        let board_commit_r = FixedPoint::from_inner(ecc_chip, board_commit_r);

        // [rcv] ValueCommitR
        board_commit_r.mul(layouter.namespace(|| "[rcv]BoardCommitR"), rcv)?
    };

    // [v] ValueCommitV + [rcv] ValueCommitR
    commitment.add(layouter.namespace(|| "cv"), &blind)
}
