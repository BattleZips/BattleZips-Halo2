// // use crate::board::board_chip::BoardChipConfig;
// use halo2_proofs::{
//     arithmetic::FieldExt,
//     circuit::{Layouter, Value},
//     plonk::{ConstraintSystem, Error, TableColumn},
// };
// use std::collections::HashMap;
// use std::marker::PhantomData;

// /// A lookup table representing a linearized 10x10 cartesian coordinate game board
// /// Incrementally assign cells for ship placement to identify overlaps
// #[derive(Debug, Clone)]
// pub(super) struct BoardTable<F: FieldExt> {
//     coordinates: TableColumn,
//     placement: TableColumn,
//     _marker: PhantomData<F>,
// }

// impl<F: FieldExt> BoardTable<F> {
//     pub(super) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
//         let coordinates = meta.lookup_table_column();
//         let placement = meta.lookup_table_column();
//         Self {
//             coordinates,
//             placement,
//             _marker: PhantomData,
//         }
//     }
//     // 10 * (ship[0] + j * (1 - ship[2])) [][][][][] + ship[1] + j * ship[2];
//     pub(super) fn load(
//         &self,
//         layouter: &mut impl Layouter<F>,
//         ships: &[[Value<F>; 3]; 5],
//     ) -> Result<(), Error> {
//         // compute the linearized coordinates of the 17 cells assigned
//         // ship example of (1, 8, 1)[len 5]: [18, 17, 16, 15, 14]
//         let ship_lengths: [usize; 5] = [5, 4, 3, 3, 2];
//         // hashmap tracks occurence of each coordinate
//         // implies collision if there are not 17 entries that lookup to 1
//         let mut placements: HashMap<Value<F>, usize> = HashMap::new();
//         for i in 0..ships.len() {
//             let ship = ships[i];
//             for j in 0..ship_lengths[i] {
//                 // linearize at 10^1 for x pos and add j length if z = 0
//                 let horizontal_z = Value::known(F::from(10u64))
//                     * (ship[0]
//                         + Value::known(F::from(j as u64)) * (Value::known(F::from(1)) - ship[2]));
//                 // 10^0 for y pos and add j length if z = 1
//                 let vertical_z = ship[1] + Value::known(F::from(j as u64)) * ship[2];
//                 let coordinate = horizontal_z + vertical_z;
//                 // evaluate coordinate for both vertical and horizontal then collapse in one expression
//                 let coordinate = match placements.get(coordinate.into_field()) {
//                     Some(value) => placements.insert(coordinate, value + 1),
//                     None => placements.insert(coordinate, 1),
//                 };
//             }
//         }
//         // insert placement values into columns
//         let placements: [Vec<usize>; 2] =
//             placements
//                 .keys()
//                 .fold([vec![], vec![]], |mut columns, key| {
//                     columns[0].push(*key);
//                     columns[1].push(*placements.get(key).unwrap());
//                     columns
//                 });

//         layouter.assign_table(
//             || "Load Board Table",
//             |mut table| {
//                 for i in 0..placements[0].len() {
//                     // assign linearized (x, y)
//                     table.assign_cell(
//                         || "assign board coordinate cell",
//                         self.coordinates,
//                         i,
//                         || Value::known(F::from(placements[0][i] as u64)),
//                     )?;
//                     // assign number of ship parts assigned to this cell
//                     table.assign_cell(
//                         || "assign board value cell",
//                         self.coordinates,
//                         i,
//                         || Value::known(F::from(placements[1][i] as u64)),
//                     )?;
//                 }
//                 Ok(())
//             },
//         )
//     }
// }
