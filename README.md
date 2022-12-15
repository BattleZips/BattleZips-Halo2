# BattleZips V2
BattleZips Halo 2 implementation

11.20.22: See `src/placement/circuit.rs` for demonstrable progress

Board Validity Circuit
  - [x] Single Ship Placement Chip
  - [ ] Transpose Placements to Board Chip
  - [ ] EdDSA signed poseidon hash of board commitment

Shot Circuit
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
