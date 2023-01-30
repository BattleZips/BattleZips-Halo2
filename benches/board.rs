// use {
//     battlezips_v2::{
//         chips::board::BoardConfig,
//         circuits::board::BoardCircuit,
//         utils::{board::Board, deck::Deck, ship::DEFAULT_WITNESS_OPTIONS},
//     },
//     criterion::{criterion_group, criterion_main, Criterion},
//     halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as Poseidon, P128Pow5T3},
//     halo2_proofs::{
//         arithmetic::FieldExt,
//         pasta::{vesta, Fp},
//         plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
//         poly::commitment::Params,
//         transcript::{Blake2bRead, Blake2bWrite, Challenge255},

//     },
//     rand::rngs::OsRng,
// };

// // The number of columns in the constraint system.
// const K: u32 = 12;

// fn benchmark(c: &mut Criterion) {
//     // construct battleship board pattern #1
//     let board = Board::from(&Deck::from([
//         Some((3, 3, true)),
//         Some((5, 4, false)),
//         Some((0, 1, false)),
//         Some((0, 5, true)),
//         Some((6, 1, false)),
//     ]));
//     // take the poseidon hash of the board state as the public board commitment
//     let board_commitment =
//         Poseidon::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([Fp::from_u128(
//             board.state(DEFAULT_WITNESS_OPTIONS).lower_u128(),
//         )]);
//     // construct BoardValidity circuit
//     let circuit = BoardCircuit::<P128Pow5T3, Fp>::new(
//         board.witness(DEFAULT_WITNESS_OPTIONS),
//         board.state(DEFAULT_WITNESS_OPTIONS),
//     );
//     // Initialize the polynomial commitment parameters
//     let params: Params<vesta::Affine> = Params::new(K);
//     // Initialize the proving key
//     let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
//     let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

//     let mut rng = OsRng;

//     // bench proof creation (IDK why here?)
//     c.bench_function("prover", |b| {
//         b.iter(|| {
//             // Create a proof
//             let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
//             create_proof(&params, &pk, &[circuit], &[&[]], &mut rng, &mut transcript)
//                 .expect("proof generation should not fail")
//         })
//     });

//     // Create a proof
//     let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
//     create_proof(&params, &pk, &[circuit], &[&[]], &mut rng, &mut transcript)
//         .expect("proof generation should not fail");
//     let proof = transcript.finalize();

//     c.bench_function("verifier", |b| {
//         b.iter(|| {
//             let strategy = SingleVerifier::new(&params);
//             let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
//             assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
//         });
//     });
// }

// criterion_group!(benches, benchmark);
// criterion_main!(benches);
