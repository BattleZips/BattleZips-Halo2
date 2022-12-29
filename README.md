# BattleZips V2
BattleZips Halo 2 implementation

TODO: 
  - FIX WITHOUT_WITNESS BY USING VALUE::UNKNOWN
  - Replace Poseidon Hash with Pedersen Commitment

## Circuits

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

## Chips
TODO
Note: does not include `BoardChip` and `ShotChip`, only auxiliary chips used by the main circuits

### Bitify

### Placement

### Transpose

## Todo
 - EdDSA Signature Verification of `board_commitment` for shot and board
 - final file structure refactor
 - chip unit testing (test most functionality @ component chip level)
 - production / real proof generation (basic)
 - unit test full game
 - full docs check


## tests

### board
 - [x] 2x random board valid board proofs
 - [x] try to place both a horizontal and vertical commitment
 - [x] try to place neither a horizontal nor vertial commitment (not place a ship)
 - [x] try to use a ship commitment with non-consecutive bits
 - [x] try to add an extra non-consecutive bit to a ship commitment
 - [ ] try to use an oversized ship commitment (extra bit added consecutively)
 - [ ] try to use an undersized ship commitment
 - [ ] try to place a ship that is technically consecutive but exceeds board row/col length of 10 (ex: 59, 60, 61)
 - [ ] try to place a ship that collides with another ship (without transpose)
 - [ ] try to place a ship that collides with another ship (with transpose)
 - [ ] try to provide wrong public board commitment

### shot
 - [x] 2x hit = true valid shot proofs
 - [x] 2x hit = false valid shot proofs
 - [x] try assert hit != 0 or 1
 - [x] try to assert a hit when the shot missed
 - [x] try to assert a shot when the hit missed
 - [x] try to make a shot commitment of 0 (no shot)
 - [x] try to make a shot commitment where multiple bits are flipped (multiple shots in one turn)
 - [x] try to make a shot commitment where there are multiple hits (extension of multiple shots)
 - [x] try to provide wrong public board commitment
 - [x] try to provide wrong public hit assertion
 - [x] try to provide wrong public shot commitment

### integration test
 - alice board placement
 - bob board placement
 - alice makes 17 hits
 - bob makes 16 misses
 - does not use mock prover, uses real proofs
