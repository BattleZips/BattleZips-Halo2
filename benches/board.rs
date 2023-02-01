use {
    battlezips_v2::{
        chips::board::BoardConfig,
        circuits::board::BoardCircuit,
        utils::{
            binary::BinaryValue, board::Board, deck::Deck, pedersen::pedersen_commit,
            ship::DEFAULT_WITNESS_OPTIONS, shot::serialize,
        },
    },
    criterion::{criterion_group, criterion_main, Criterion},
    halo2_proofs::{
        arithmetic::{CurveAffine, Field, FieldExt},
        pasta::{group::Curve, pallas, vesta},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    },
    rand::rngs::OsRng,
};

// The number of columns in the constraint system.
const K: u32 = 12;

fn benchmark(c: &mut Criterion) {
    // construct battleship board pattern #1
    let board = Board::from(&Deck::from([
        Some((3, 3, true)),
        Some((5, 4, false)),
        Some((0, 1, false)),
        Some((0, 5, true)),
        Some((6, 1, false)),
    ]));
    // sample a random trapdoor value for commitment
    let trapdoor = pallas::Scalar::random(&mut OsRng);
    // marshall the board state into a pallas base field element
    let message = pallas::Base::from_u128(board.state(DEFAULT_WITNESS_OPTIONS).lower_u128());
    // commit to the board state
    let commitment = {
        let commitment = pedersen_commit(&message, &trapdoor).to_affine();
        let x = commitment.clone().coordinates().unwrap().x().to_owned();
        let y = commitment.clone().coordinates().unwrap().y().to_owned();
        vec![x, y]
    };
    // construct Board circuit
    let circuit = BoardCircuit::new(
        board.witness(DEFAULT_WITNESS_OPTIONS),
        board.state(DEFAULT_WITNESS_OPTIONS),
        trapdoor,
    );
    // Initialize the polynomial commitment parameters
    let params: Params<vesta::Affine> = Params::new(K);
    // Initialize the proving key
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    // benchmark proof creation
    c.bench_function("board_prover", |b| {
        b.iter(|| {
            // Create a proof
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof(
                &params,
                &pk,
                &[circuit],
                &[&[&commitment]],
                &mut OsRng,
                &mut transcript,
            )
            .expect("proof generation should not fail")
        })
    });

    // create proof for verifier benchmark
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], &[&[&commitment]], &mut OsRng, &mut transcript)
        .expect("proof generation should not fail");
    let proof = transcript.finalize();

    // benchmark proof verification
    c.bench_function("board_verifier", |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[&commitment]], &mut transcript).is_ok());
        });
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
