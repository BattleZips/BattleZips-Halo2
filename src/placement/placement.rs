// use crate::{
//     bits2num::bits2num::{Bits2NumConfig, Bits2NumChip},
//     utils::ship::{Placement, ShipType, ShipUtilities}
// };
// use std::marker::PhantomData;

// use halo2_proofs::{
//     arithmetic::FieldExt,
//     circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
//     plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
//     poly::Rotation,
// };

// // | placements | bits | s_mul |
// // |------------|------|-------|
// // | h          |  0   | s_mul |
// // | v          |  1   |       |
// // 

// // Chip columns/ rows in 
// #[derive(Clone, Debug)]
// struct PlacementConfig {
//     bits2num: Bits2NumConfig,
//     placements: Column<Advice>,
//     bits: Column<Advice>,

// }

// trait PlacementInstructions<F: FieldExt, const T: ShipType>: Chip<F> {

//     /**
//      * Standard chip configuration API
//      */
//     fn configure(meta: &mut ConstraintSystem<F>) -> PlacementConfig;

//     /**
//      * Given a `ship` Placement, assign the placement variables
//      *
//      * @param ship - the {x, y, z} dictating ship placement
//      */
//     fn load_placements(&self, layouter: impl Layouter<F>, ship: Placement<T>) -> Result<(), String>;

//     // /**
//     //  * Combine horizontal and vertical placements into one integer
//     //  * @dev: actions
//     //  *  - set selector for gate checking either horizontal or vertical placement = 1
//     //  *  - sum h + v and assign for decomposition
//     //  */
//     // fn composite_placement(&self, layouter: impl Layouter<F>) -> Result<(), String>;

//     // /**
//     //  * Decompose Sum(h, v) into 100 bit number & assert that only 5 bits are flipped
//     //  */
//     // fn decompose_placement(&self, layouter: impl Layouter<F>) -> Result<(), String>;

//     // /**
//     //  * 
//     //  * @dev accomplished by checking in windows of SHIP_LENGTH size for cells that are all flipped
//     //  * @dev most be adjacent % 10
//     //  */
//     // fn adjacent_placement(&self, layouter: impl Layouter<F>) -> Result<(), String>;

//     // /** */
// }

// /// Constructs a cell and a variable for the circuit.
// /// S: SHIP_SIZE
// #[derive(Clone, Debug)]
// pub struct PlacementChip<F: FieldExt, const S: usize> {
//     /// Assigns a cell for the value.
//     placements: [AssignedCell<F, F>; 2],
//     /// Constructs bits variable for the circuit.
//     bits: [Value<F>; S],
// }

// impl<F: FieldExt, const T: ShipType> PlacementInstructions<F, T> for PlacementChip<F, T> {

//     fn configure(meta: &mut ConstraintSystem<F>) -> PlacementConfig {
//         let bits2num = Bits2NumChip::<_, 100>::configure(meta);
//         let placements = meta.advice_column();
//         let bits = meta.advice_column();
//         PlacementConfig { bits2num, placements, bits }
//     }

//     fn load_placements(&self, layouter: impl Layouter<F>, ship: Placement<T>) -> Result<(), String> {
//         // compute placement values
//         let horizontal = Value::known(F::from(ship.export_element(false)));
//         let vertical = Value::known(F::from(ship.export_element(true)));
//         // assign placement values to cells
//         layouter.assign_region
//     }

// }
