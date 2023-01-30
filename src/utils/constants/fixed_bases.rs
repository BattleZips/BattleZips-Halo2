use {
    halo2_gadgets::ecc::{
        chip::{constants::H, BaseFieldElem, FixedPoint, FullScalar, ShortScalar },
        FixedPoints,
    },
    halo2_proofs::pasta::pallas,
};

pub mod board_commit_v;
pub mod board_commit_r;


#[derive(Copy, Clone, Debug, Eq, PartialEq)]
// A sum type for both full-width and short bases. This enables us to use the
// shared functionality of full-width and short fixed-base scalar multiplication.
pub enum BoardFixedBases {
    BoardCommitV,
    BoardCommitR,
}

/// BoardCommitV is used in scalar mul with a base field element. (trapdoor)
/// This is used for the witnessed board state binding commitment
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BoardCommitV;

/// BoardCommitR is used in scalar mul with a full width scalar.
/// This is used as a blinding commitment for the board state
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BoardCommitR;

/// VESTIGIAL / NOT NEEDED ASIDES FROM ITEM SIGNATURE FOR FIXED POINTS
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BoardCommitQ;

impl FixedPoints<pallas::Affine> for BoardFixedBases {
    type Base = BoardCommitV;
    type FullScalar = BoardCommitR;
    type ShortScalar = BoardCommitQ;
}

impl FixedPoint<pallas::Affine> for BoardCommitV {
    type FixedScalarKind = BaseFieldElem;

    fn generator(&self) -> pallas::Affine {
        board_commit_v::generator()
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        board_commit_v::U.to_vec()
    }

    fn z(&self) -> Vec<u64> {
        board_commit_v::Z.to_vec()
    }
}

impl FixedPoint<pallas::Affine> for BoardCommitR {
    type FixedScalarKind = FullScalar;

    fn generator(&self) -> pallas::Affine {
        board_commit_r::generator()
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        board_commit_r::U.to_vec()
    }

    fn z(&self) -> Vec<u64> {
        board_commit_r::Z.to_vec()
    }
}

impl FixedPoint<pallas::Affine> for BoardCommitQ {
    type FixedScalarKind = ShortScalar;

    fn generator(&self) -> pallas::Affine {
        board_commit_r::generator()
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        board_commit_r::U.to_vec()
    }

    fn z(&self) -> Vec<u64> {
        board_commit_r::Z.to_vec()
    }
}
