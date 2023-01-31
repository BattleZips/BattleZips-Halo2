use {
    crate::{
        chips::shot::{ShotChip, ShotConfig},
        utils::binary::BinaryValue,
    },
    halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        pasta::pallas,
        plonk::{Circuit, ConstraintSystem, Error},
    },
};

#[derive(Debug, Clone, Copy)]
pub struct ShotCircuit {
    pub board: BinaryValue,
    pub board_commitment_trapdoor: pallas::Scalar,
    pub shot: BinaryValue,
    pub hit: BinaryValue,
}

impl Circuit<pallas::Base> for ShotCircuit {
    type Config = ShotConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        // @TODO FIX
        ShotCircuit::new(
            self.board,
            self.board_commitment_trapdoor,
            self.shot,
            self.hit,
        )
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        ShotChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        Ok(ShotChip::new(config).synthesize(
            layouter,
            self.board,
            self.board_commitment_trapdoor,
            self.shot,
            self.hit,
        )?)
    }
}

impl ShotCircuit {
    /**
     * Construct a new shot circuit to evaluate whether a valid shot hits a ship
     *
     * @param board - private board placement
     * @param board_commitment_trapdoor - trapdoor to the board commitment
     * @param shot - x, y coordinates serialized into a shot commitment
     * @param hit - assertion that the shot either hits or misses the decomposed board (constrained 0 or 1)
     * @return - instantiated BoardCircuit object containing BoardGadget
     */
    pub fn new(
        board: BinaryValue,
        board_commitment_trapdoor: pallas::Scalar,
        shot: BinaryValue,
        hit: BinaryValue,
    ) -> ShotCircuit {
        ShotCircuit {
            board,
            board_commitment_trapdoor,
            shot,
            hit,
        }
    }
}

#[cfg(test)]
mod test {

    use {
        super::*,
        crate::utils::{
            binary::U256, board::Board, deck::Deck, pedersen::pedersen_commit,
            ship::DEFAULT_WITNESS_OPTIONS, shot::serialize,
        },
        halo2_proofs::{
            arithmetic::{CurveAffine, Field},
            dev::{FailureLocation, MockProver, VerifyFailure},
            pasta::{group::Curve, pallas, vesta},
            plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Any, SingleVerifier},
            poly::commitment::Params,
            transcript::{Blake2bRead, Blake2bWrite, Challenge255},
        },
        rand::rngs::OsRng,
    };

    #[test]
    fn valid_hit_0() {
        // construct valid battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // serialize a shot at (3, 5) into `53u256`
        let shot = serialize::<1>([3], [5]);
        // assert a hit and wrap in u256
        let hit = BinaryValue::from_u8(1);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove a valid hit assertion for a given board commitment to board pattern 1
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn valid_hit_1() {
        // construct valid battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // serialize a shot at (9, 8) into `89u256`
        let shot = serialize::<1>([9], [8]);
        // assert a hit and wrap in u256
        let hit = BinaryValue::from_u8(1);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove a valid hit assertion for a given board commitment to board pattern 2
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn valid_miss_0() {
        // construct valid battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // serialize a shot at (4, 3) into `34u256`
        let shot = serialize::<1>([4], [3]);
        // assert a miss and wrap in u256
        let hit = BinaryValue::from_u8(0);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove a valid miss assertion for a given board commitment to board pattern 1
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn valid_miss_1() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // serialize a shot at (3, 3) into `33u256`
        let shot = serialize::<1>([3], [3]);
        // assert a miss and wrap in u256
        let hit = BinaryValue::from_u8(0);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove a valid miss assertion for a given board commitment on board pattern 2
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn invalid_non_boolean_hit_assertion() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // serialize a shot at (9, 8) into `89u256`
        let shot = serialize::<1>([9], [8]);
        // assert a non-boolean value and wrap in u256
        let hit = BinaryValue::from_u8(2);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove a non-boolean hit assertions will fail verification
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::ConstraintNotSatisfied {
                    // check violation of boolean input constraint
                    constraint: (
                        (21, "boolean hit assertion").into(),
                        0,
                        "asserted hit value is boolean"
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (0, "load private ShotChip advice values").into(),
                        offset: 4
                    },
                    cell_values: vec![(((Any::Advice, 4).into(), 0).into(), String::from("0x2"))]
                },
                VerifyFailure::ConstraintNotSatisfied {
                    // counted counted hit # does not match asserted hit #
                    constraint: (
                        (23, "constrain shot running sum output").into(),
                        1,
                        "Public hit assertion matches private witness"
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (4, "shot running sum output checks").into(),
                        offset: 0
                    },
                    cell_values: vec![
                        (((Any::Advice, 5).into(), 0).into(), String::from("0x2")),
                        (((Any::Advice, 7).into(), 0).into(), String::from("1"))
                    ]
                }
            ])
        );
    }

    #[test]
    fn invalid_assert_hit_when_miss() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // serialize a shot at (8, 8) into `88u256`
        let shot = serialize::<1>([8], [8]);
        // assert a hit and wrap in u256
        let hit = BinaryValue::from_u8(1);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove that asserting a hit when shot misses fails verification
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                // fail constraint: count 0 hits but 1 inputted
                constraint: (
                    (23, "constrain shot running sum output").into(),
                    1,
                    "Public hit assertion matches private witness"
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (4, "shot running sum output checks").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::Advice, 5).into(), 0).into(), String::from("1")),
                    (((Any::Advice, 7).into(), 0).into(), String::from("0"))
                ]
            }])
        );
    }

    #[test]
    fn invalid_assert_miss_when_hit() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // serialize a shot at (7, 1) into `17u256`
        let shot = serialize::<1>([7], [1]);
        // assert a miss and wrap in u256
        let hit = BinaryValue::from_u8(0);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove that asserting a miss when shot hits fails verification
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                // fail constraint: count 1 hits but 0 inputted
                constraint: (
                    (23, "constrain shot running sum output").into(),
                    1,
                    "Public hit assertion matches private witness"
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (4, "shot running sum output checks").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::Advice, 5).into(), 0).into(), String::from("0")),
                    (((Any::Advice, 7).into(), 0).into(), String::from("1"))
                ]
            }])
        );
    }

    #[test]
    fn invalid_no_shot() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // set the shot commitment to be `0u256`
        let shot = BinaryValue::new(U256::from([0, 0, 0, 0]));
        // assert a miss and wrap in u256
        let hit = BinaryValue::from_u8(0);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove that providing no shot commitment fails verification
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                // fail constraint: 0 shots counted when 1 expected
                constraint: (
                    (23, "constrain shot running sum output").into(),
                    0,
                    "Shot only fires at one board cell"
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (4, "shot running sum output checks").into(),
                    offset: 0
                },
                cell_values: vec![(((Any::Advice, 6).into(), 0).into(), String::from("0")),]
            }])
        );
    }

    #[test]
    fn invalid_multi_shot() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // serialize one shot that misses at 9, 9 and one that hits at 3, 3 in a single commitment
        let shot = serialize::<2>([3, 9], [3, 9]);
        // assert a hit and wrap in u256
        let hit = BinaryValue::from_u8(1);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove that attempting multiple shots in one shot commitment fails verification
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                // fail constraint: 2 shots counted when 1 expected
                constraint: (
                    (23, "constrain shot running sum output").into(),
                    0,
                    "Shot only fires at one board cell"
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (4, "shot running sum output checks").into(),
                    offset: 0
                },
                cell_values: vec![(((Any::Advice, 6).into(), 0).into(), String::from("0x2")),]
            }])
        );
    }

    #[test]
    fn invalid_multi_hit() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // serialize 3 shots that all hit at (0, 0), (1, 0), (2, 0)
        let shot = serialize::<3>([0, 1, 2], [0, 0, 0]);
        // assert a hit and wrap in u256
        // @dev could either constrain this way which will count wrong # of hits, or nonzero hit assertion
        let hit = BinaryValue::from_u8(1);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove that finding multiple hits in one shot commitment fails verification
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::ConstraintNotSatisfied {
                    // fail constraint: 3 shots counted when 1 expected
                    constraint: (
                        (23, "constrain shot running sum output").into(),
                        0,
                        "Shot only fires at one board cell"
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (4, "shot running sum output checks").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::Advice, 6).into(), 0).into(), String::from("0x3")),]
                },
                VerifyFailure::ConstraintNotSatisfied {
                    // fail constraint: count 1 hits but 0 inputted
                    constraint: (
                        (23, "constrain shot running sum output").into(),
                        1,
                        "Public hit assertion matches private witness"
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (4, "shot running sum output checks").into(),
                        offset: 0
                    },
                    cell_values: vec![
                        (((Any::Advice, 5).into(), 0).into(), String::from("1")),
                        (((Any::Advice, 7).into(), 0).into(), String::from("0x3"))
                    ]
                }
            ])
        );
    }

    #[test]
    fn invalid_commitment() {
        // construct battleship board pattern 2
        let board = Board::from(&Deck::from([
            Some((3, 4, false)),
            Some((9, 6, true)),
            Some((0, 0, false)),
            Some((0, 6, false)),
            Some((6, 1, true)),
        ]));
        // serialize a shot at (0, 0) into `1u256`
        let shot = serialize::<1>([0], [0]);
        // assert a hit and wrap in u256
        let hit = BinaryValue::from_u8(1);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state and add one to the x coordinate to make it incorrect
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned() + pallas::Base::one();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove that providing an invalid board commitment fails verification
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Advice, 2).into(),
                    location: FailureLocation::InRegion {
                        region: (12, "complete point addition").into(),
                        offset: 1
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 0 }
                }
            ])
        );
    }

    #[test]
    fn invalid_public_board_commitment() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // serialize a shot at (0, 0) into `1u256`
        let shot = serialize::<1>([0], [0]);
        // assert a hit and wrap in u256
        let hit = BinaryValue::from_u8(0);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        // add 1 to public_outputs[0] to throw off public assertion to board commitment
        let public_outputs = vec![
            commitment.0 + pallas::Base::one(),
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove that providing an invalid board commitment publicly fails verification
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Advice, 2).into(),
                    location: FailureLocation::InRegion {
                        region: (12, "complete point addition").into(),
                        offset: 1
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 0 }
                }
            ])
        );
    }

    #[test]
    fn invalid_public_shot_commitment() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // serialize a shot at (0, 0) into `1u256`
        let shot = serialize::<1>([0], [0]);
        // assert a miss and wrap in u256
        let hit = BinaryValue::from_u8(0);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state and add one to the x coordinate to make it incorrect
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        // add 1 to public_outputs[2] to throw off public assertion to shot commitment
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()) + pallas::Base::one(),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove that providing an invalid shot commitment publicly fails verification
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Advice, 4).into(),
                    location: FailureLocation::InRegion {
                        region: (0, "load private ShotChip advice values").into(),
                        offset: 3
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                }
            ])
        );
    }

    #[test]
    fn invalid_public_hit_assertion() {
        // construct battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // serialize a shot at (1, 6) into `61u256`
        let shot = serialize::<1>([1], [6]);
        // assert a hit and wrap in u256
        let hit = BinaryValue::from_u8(1);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state and add one to the x coordinate to make it incorrect
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        // add 1 to public_outputs[3] to throw off public assertion to hit
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()) + pallas::Base::one(),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // prove that providing an invalid hit publicly fails verification
        let prover = MockProver::run(11, &circuit, vec![public_outputs]).unwrap();
        // expect failure
        assert_eq!(
            prover.verify(),
            Err(vec![
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: (
                        (23, "constrain shot running sum output").into(),
                        1,
                        "Public hit assertion matches private witness"
                    )
                        .into(),
                    location: FailureLocation::InRegion {
                        region: (4, "shot running sum output checks").into(),
                        offset: 0
                    },
                    cell_values: vec![
                        (((Any::Advice, 5).into(), 0).into(), String::from("1")),
                        (((Any::Advice, 7).into(), 0).into(), String::from("0")),
                    ]
                },
                VerifyFailure::Permutation {
                    column: (Any::Advice, 4).into(),
                    location: FailureLocation::InRegion {
                        region: (0, "load private ShotChip advice values").into(),
                        offset: 4
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 3 }
                }
            ])
        );
    }

    #[test]
    fn production() {
        // construct valid battleship board pattern 1
        let board = Board::from(&Deck::from([
            Some((3, 3, true)),
            Some((5, 4, false)),
            Some((0, 1, false)),
            Some((0, 5, true)),
            Some((6, 1, false)),
        ]));
        // serialize a shot at (3, 5) into `53u256`
        let shot = serialize::<1>([3], [5]);
        // assert a hit and wrap in u256
        let hit = BinaryValue::from_u8(1);
        // sample a random trapdoor value for commitment
        let trapdoor = pallas::Scalar::random(&mut OsRng);
        // marshall the board state into a pallas base field element
        let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
        // commit to the board state
        let commitment = {
            let commitment = pedersen_commit(&message, &trapdoor).to_affine();
            let x = commitment.clone().coordinates().unwrap().x().to_owned();
            let y = commitment.clone().coordinates().unwrap().y().to_owned();
            (x, y)
        };
        // assign public output values
        let public_outputs = vec![
            commitment.0,
            commitment.1,
            pallas::Base::from_u128(shot.lower_u128()),
            pallas::Base::from_u128(hit.lower_u128()),
        ];
        // construct Shot circuit
        let circuit = ShotCircuit::new(board.state(DEFAULT_WITNESS_OPTIONS), trapdoor, shot, hit);
        // Initialize the polynomial commitment parameters
        let params: Params<vesta::Affine> = Params::new(11);
        // Initialize the proving key
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
        // create proof for verifier benchmark
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[&[&public_outputs]],
            &mut OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&public_outputs]],
            &mut transcript
        )
        .is_ok());
    }

    // #[test]
    // fn print_circuit() {
    //     use plotters::prelude::*;
    //     let board = Board::from(&Deck::from([
    //         Some((3, 4, false)),
    //         Some((9, 6, true)),
    //         Some((0, 0, false)),
    //         Some((0, 6, false)),
    //         Some((6, 1, true)),
    //     ]));
    //     let shot = serialize::<1>([1], [6]);
    //     let hit = BinaryValue::from_u8(1);
    //     let circuit =
    //         ShotCircuit::<P128Pow5T3, Fp>::new(board.state(DEFAULT_WITNESS_OPTIONS), shot, hit);
    //     let root = BitMapBackend::new("shot_layout.png", (1920, 1080)).into_drawing_area();
    //     root.fill(&WHITE).unwrap();
    //     let root = root
    //         .titled("Shot Circuit Layout", ("sans-serif", 60))
    //         .unwrap();
    //     CircuitLayout::default()
    //         // You can optionally render only a section of the circuit.
    //         .view_width(0..2)
    //         .view_height(0..16)
    //         // You can hide labels, which can be useful with smaller areas.
    //         .show_labels(false)
    //         // Render the circuit onto your area!
    //         // The first argument is the size parameter for the circuit.
    //         .render(12, &circuit, &root)
    //         .unwrap();
    // }
}
