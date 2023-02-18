use {
    crate::circuits::board::BoardCircuit,
    crate::utils::{
        board::Board, deck::Deck, pedersen::pedersen_commit, ship::DEFAULT_WITNESS_OPTIONS,
    },
    halo2_proofs::{
        arithmetic::{CurveAffine, Field, FieldExt},
        pasta::{group::Curve, pallas, vesta, EpAffine, EqAffine, Fp, Fq},
        plonk::{create_proof, keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
        poly::commitment::Params,
        transcript::{Blake2bWrite, Challenge255},
    },
    rand::rngs::OsRng,
    serde_wasm_bindgen::{from_value, to_value},
    wasm_bindgen::prelude::*,
};

pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen]
pub fn prove_board(placed_ships: JsValue) -> JsValue {
    let array: [Option<(u8, u8, bool)>; 5] =
        from_value::<[Option<(u8, u8, bool)>; 5]>(placed_ships).unwrap();
    let board: Board = Board::from(&Deck::from(array));
    // sample a random trapdoor value for commitment
    let trapdoor: Fq = pallas::Scalar::random(&mut OsRng);
    // marshall the board state into a pallas base field element
    let message: Fp = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
    // commit to the board state
    let commitment: Vec<Fp> = {
        let commitment: EpAffine = pedersen_commit(&message, &trapdoor).to_affine();
        let x: Fp = commitment.clone().coordinates().unwrap().x().to_owned();
        let y: Fp = commitment.clone().coordinates().unwrap().y().to_owned();
        vec![x, y]
    };

    // construct Board circuit
    let circuit: BoardCircuit = BoardCircuit::new(
        board.witness(DEFAULT_WITNESS_OPTIONS),
        board.state(DEFAULT_WITNESS_OPTIONS),
        trapdoor,
    );

    let params: Params<vesta::Affine> = Params::new(12);
    // Initialize the proving key
    let vk: VerifyingKey<EqAffine> =
        keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk: ProvingKey<EqAffine> =
        keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
    // create proof for verifier benchmark
    let mut transcript: Blake2bWrite<Vec<u8>, EqAffine, Challenge255<EqAffine>> =
        Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&[&commitment]],
        &mut OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    to_value(&transcript.finalize()).unwrap()
}
