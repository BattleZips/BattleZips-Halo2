# BattleZips-Halo2

## Code
x86_64-unknown-linux-gnu was the development target for this codebase. 

Unit test the board and shot circuits
```
cargo test
```

Build the wasm for (BattleZipV2-Frontend)[https://github.com/BattleZips/BattleZipsV2-Frontend]:
```
cargo build --release --target=wasm32-unknown-unknown
# find the outputted wasm artifacts
ls ./target/wasm32-unknown-unknown/release
```

## Circuits
### Board Circuit
  - Inputs array of 10 private ship commitments corresponding to [`H5`, `V5`, `H4`, `V4`, `H3a`, `V3a`, `H3b`, `V3b`, `H2`, `V2`]
  - For each pair ex: (`H5`, `V5`) constrain at least one of the values to be equal to `0`
  - Constrained binary decomposition of all ship commitments into bits
  - For each pair of decomposed bits, constrain individual ship placement via PlacementChip
  - Once all placements pass, constrained transposition all decomposed ship commitments into one decomposed board commitment
  - Constrained binary recomposition of board commitment bits into a single board state value
  - Constrained pedersen commitment of board state into board commitment
  - Publicly export board commitment from zero knowledge proof

### Shot Circuit
  - Inputs `board_state`, `board_commitment`, `shot_commitment`, `hit_assertion`
     - `board_state` - private 100-bit number (constrained in Board Circuit) with flipped bits representing shot placements
     - `board_commitment` - the pedersen comitment of `board_state`
     - `shot_commitment` - public 100-bit number constrained to have only 1 bit flipped representing serialized shot coordinate
     - `hit_assertion` - public boolean statement on whether `shot_commitment`'s flipped bit is also flipped in `board_state`
  - Constrains `hit_assertion` to be equal to either `0` or `1`
  - Constrains `shot_commitment` to have exactly 1 flipped (true) bit when decomposed into binary
  - Constrains `hit_assertion` to be equal to the number of rows where `shot_commitment` and `board_state` both have a flipped bit
  - Constrains the proper computation of the Pedersen commitment of `board_state`
  - Constrains `board_commitment` input advice to equal to the computed pedersen commitment of `board_state`
  - Publicly export `board_commitment`, `shot_commitment`, `hit_assertion` from the zero knowledge proof

## License
BattleZipsV2 is license under GNU GPLv3. Go nuts.

## Contact Project Maintainer
Join the [BattleZips Discord channel](https://discord.gg/NEyTSmjewn)

## Motivation
[Battleships](https://www.hasbro.com/common/instruct/battleship.pdf) is an adversarial, two-player board game centered around a hidden information mechanic. BattleZips-Halo2 demonstrates how one constrains computations for a Battleship game with the intent that developers can extrapolate their own projects in the [zcash/Halo2](https://github.com/zcash/halo2) proving scheme. 

## On ZK State Channels
Halo2 recursion eluded us. After quickly putting together a [PCD-based recursion prototype in Plonky2](https://github.com/BattleZips/BattleZips-Plonky2), we received feedback that IVC-based accumulation would be sufficient for this case. We will revisit in the future with the KZG fork. 

Todo:
 - figure out KZG fork
 - determine how to make circuit more efficient
 - determine how to use accumulation to build IVC state channel