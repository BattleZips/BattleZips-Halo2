use {
    crate::circuits::{board::BoardCircuit, shot::ShotCircuit},
    crate::utils::{
        binary::BinaryValue, board::Board, deck::Deck, pedersen::pedersen_commit,
        ship::DEFAULT_WITNESS_OPTIONS, shot::serialize,
    },
    halo2_proofs::{
        arithmetic::{CurveAffine, Field, FieldExt},
        circuit::Value,
        pasta::{group::Curve, pallas, vesta, EpAffine, EqAffine, Fp, Fq},
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier,
            VerifyingKey,
        },
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    },
    rand::rngs::OsRng,
    serde::{Deserialize, Serialize},
    serde_wasm_bindgen::{from_value, to_value},
    wasm_bindgen::prelude::*,
};

pub use wasm_bindgen_rayon::init_thread_pool;

// Struct to implement Serialize & Deserlize on for easy JS conversion
#[derive(Serialize, Deserialize)]
pub struct BattleZipsWASM {
    commitment: Vec<[u8; 32]>,
    proof: Vec<u8>,
}

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
    let bittified_commitment = commitment
        .into_iter()
        .map(|fp| BinaryValue::from_fp(fp).to_repr())
        .collect::<Vec<[u8; 32]>>();
    // Return BattleZipsWASM struct
    to_value(&BattleZipsWASM {
        commitment: bittified_commitment,
        proof: transcript.finalize(),
    })
    .unwrap()
}

#[wasm_bindgen]
pub fn verify_board(js_commitment: JsValue, js_proof: JsValue) -> bool {
    // Deserialize outputs as vector of uint8 arrays
    let deser_commitment: Vec<[u8; 32]> = from_value::<Vec<[u8; 32]>>(js_commitment).unwrap();
    // Map deserialized outputs to vector of Fp
    let commitment = deser_commitment
        .into_iter()
        .map(|bin| BinaryValue::from_repr(bin).to_fp())
        .collect::<Vec<Fp>>();
    let proof: Vec<u8> = from_value::<Vec<u8>>(js_proof).unwrap();
    let params: Params<vesta::Affine> = Params::new(12);

    // Initialize empty circuit to generate vk
    let empty_circuit = BoardCircuit::new(
        [BinaryValue::empty(); 10],
        BinaryValue::empty(),
        pallas::Scalar::random(&mut OsRng),
    );

    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");

    // Proof parsed from JS
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof(&params, &vk, strategy, &[&[&commitment]], &mut transcript).is_ok()
}

#[wasm_bindgen]
pub fn prove_shot(js_hit: JsValue, js_ships: JsValue, js_shot: JsValue) -> JsValue {
    let placed_ships: [Option<(u8, u8, bool)>; 5] =
        from_value::<[Option<(u8, u8, bool)>; 5]>(js_ships).unwrap();

    let board: Board = Board::from(&Deck::from(placed_ships));
    let parsed_shot: [u8; 2] = from_value::<[u8; 2]>(js_shot).unwrap();
    let shot = serialize::<1>([parsed_shot[0]], [parsed_shot[1]]);
    // assert a hit and wrap in u256
    let hit = BinaryValue::from_u8(from_value::<u8>(js_hit).unwrap());
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
    );
    let bittified_output = public_outputs
        .into_iter()
        .map(|fp| BinaryValue::from_fp(fp).to_repr())
        .collect::<Vec<[u8; 32]>>();
    // Return BattleZipsWASM struct
    to_value(&BattleZipsWASM {
        commitment: bittified_output,
        proof: transcript.finalize(),
    })
    .unwrap()
}

#[wasm_bindgen]
pub fn verify_shot(js_outputs: JsValue, js_proof: JsValue) -> bool {
    // Deserialize outputs as vector of uint8 arrays
    let deser_outputs: Vec<[u8; 32]> = from_value::<Vec<[u8; 32]>>(js_outputs).unwrap();
    // Map deserialized outputs to vector of Fp
    let outputs = deser_outputs
        .into_iter()
        .map(|bin| BinaryValue::from_repr(bin).to_fp())
        .collect::<Vec<Fp>>();
    let params: Params<vesta::Affine> = Params::new(11);
    let strategy = SingleVerifier::new(&params);
    let proof: Vec<u8> = from_value::<Vec<u8>>(js_proof).unwrap();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    // Initialize empty circuit to generate vk
    let empty_circuit = ShotCircuit::new(
        BinaryValue::empty(),
        pallas::Scalar::random(&mut OsRng),
        BinaryValue::empty(),
        BinaryValue::empty(),
    );

    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    verify_proof(&params, &vk, strategy, &[&[&outputs]], &mut transcript).is_ok()
}
