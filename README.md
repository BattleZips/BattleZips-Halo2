# BattleZips V2

## License
BattleZipsV2 is license under GNU GPLv3. Go nuts.

## Contact Project Maintainer
Did you find a bug in our code? Does something about BattleZipsV2 (or Halo2 in general) not make sense to you, and you'd like some guidance? Did you raise an issue that has been pending for a week? We @ BattleZips are Discord natives; join the [BattleZips Discord channel](https://discord.gg/NEyTSmjewn) to get quick help / direction!

## Circuits
We aim to bring a complete walkthrough of the codebase in mid Q1 2023; contact the project maintainer for questions otherwise!

### Board Circuit
  - Inputs array of 10 private ship commitments corresponding to [`H5`, `V5`, `H4`, `V4`, `H3a`, `V3a`, `H3b`, `V3b`, `H2`, `V2`]
  - For each pair ex: (`H5`, `V5`) constrain at least one of the values to be equal to `0`
  - Constrained binary decomposition of all ship commitments into bits
  - For each pair of decomposed bits, constrain individual ship placement via PlacementChip
  - Once all placements pass, constrained transposition all decomposed ship commitments into one decomposed board commitment
  - Constrained binary recomposition of board commitment bits into a single board state value
  - Constrained poseidon hash of board state into board commitment
    - in the future the board commitment will be signed hash and this is intermediate
  - Publicly export board commitment from zero knowledge proof

### Shot Circuit
  - Inputs `board_state`, `board_commitment`, `shot_commitment`, `hit_assertion`
     - `board_state` - private 100-bit number (constrained in Board Circuit) with flipped bits representing shot placements
     - `board_commitment` - the poseidon hash of `board_state` (to be signed hash in the future)
     - `shot_commitment` - public 100-bit number constrained to have only 1 bit flipped representing serialized shot coordinate
     - `hit_assertion` - public boolean statement on whether `shot_commitment`'s flipped bit is also flipped in `board_state`
  - Constrains `hit_assertion` to be equal to either `0` or `1`
  - Constrains `shot_commitment` to have exactly 1 flipped (true) bit when decomposed into binary
  - Constrains `hit_assertion` to be equal to the number of rows where `shot_commitment` and `board_state` both have a flipped bit
  - Constrains the proper computation of the Poseidon hash of `board_state`
  - Constrains `board_commitment` to equal the constrained computation of the poseidon hash of `board_state`
    - in the future this will be one step later as the hash will be signed
  - Publicly export `board_commitment`, `shot_commitment`, `hit_assertion` from the zero knowledge proof

## To Do
### ASAP
 - integration/ benchmark real proof generation
 - docs check
 - print circuits and official write up

## Todo future
 - use wasm exclusively
 - switch to kzg version
   - revisit whether kzg has superior recursion that can facilitate state channels

 - pedersen commitments instead of poseidon hashes
 - verify board/ shot proofs on-chain
 - front-end integration
  - basic proving of shot and board circuits
  - use 
 - lookup tables used instead of interpolating bit window equation on the fly
 - maybe: video walkthrough

## Motivation
As we seek to apply Zero Knowledge cryptography, a generalization of our goal is to build cryptographically-secured "confidential, adversarial multi-party computations". In laymans terms, it means we need a computational vehicle that allows parties to truthfully coordinate with eachother without revealing critical operating parameters that a counterparty could abuse. [Battleships](https://www.hasbro.com/common/instruct/battleship.pdf) is an adversarial, two-player board game centered around a hidden information mechanic. BattleZipsV2 demonstrates how one constrains computations for a Battleship game with the intent that developers can extrapolate their own projects in the [zcash/Halo2](https://github.com/zcash/halo2) proving scheme. 

## On ZK State Channels
Once Halo2 supports IVC recursion, this codebase will be revisited to prototype ZK State Channels with the battleship game in Halo2. This improvement will add a "Game" proof that recursively takes in Alice Board proof -> Bob Board proof -> Alice shot proof 0 -> Bob shot proof 0 -> ... Alice shot proof N; where the proof will signal a winner if 17 hits have been accumulated. This is a tool of both privacy and scalability:
 * in BattleZipsV2, each shot + the hit / miss assertions (as well as all intermediate metadata) is available publicly. State channels will provide a proof that it is a summary of "An off-chain battleship game was won by alice and lost by bob" without revealing any other information about the game
 * in BattleZipsV2, both board proofs as well as every shot proof is delivered and verified on-chain in a different transaction (on-chain integration not included for Halo2 currently). With ZK state channels, players pass proofs back and forth directly over a p2p connection, using a recursive game proof to locally check messages from the counterparty and accumulate state. Once a player has accumulated 17 hits on the opponent, they will be able to post the recursive proof on-chain in a single transaction, drastically reducing the on-chain footprint
