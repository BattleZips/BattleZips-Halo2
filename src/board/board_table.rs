// use crate::board::board_chip::BoardChipConfig;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn}
};
use std::marker::PhantomData;
use std::collections::HashMap;

/// A lookup table representing a linearized 10x10 cartesian coordinate game board
/// Incrementally assign cells for ship placement to identify overlaps
#[derive(Debug, Clone)]
pub(super) struct BoardTable<F: FieldExt> {
    coordinates: TableColumn,
    placement: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BoardTable<F> {
    pub(super) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let coordinates = meta.lookup_table_column();
        let placement = meta.lookup_table_column();
        Self {
            coordinates,
            placement,
            _marker: PhantomData,
        }
    }

    pub(super) fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        ships: &[[usize; 3]; 5],
    ) -> Result<(), Error> {
        // compute values of cells to assign
        let ship_lengths: [usize; 5] = [5, 4, 3, 3, 2];
        let mut placements:HashMap<usize, usize> = HashMap::new();
        for i in 0..ships.len() {
            let ship = ships[i];
            for j in 0..ship_lengths[i] {
                let coordinate = 10 * (ship[0] + j * (1 - ship[2])) + ship[1] + j * ship[2];
                match placements.get(&coordinate) {
                    Some(value) => placements.insert(coordinate, value + 1),
                    None => placements.insert(coordinate, 1)
                };
            }
        }
        let placements: [Vec<usize>; 2] = placements.keys().fold([vec![], vec![]], |mut columns, key| {
            columns[0].push(*key);
            columns[1].push(*placements.get(key).unwrap());
            columns
        });

        layouter.assign_table(
            || "Load Board Table",
            |mut table| {
                for i in 0..placements[0].len() {
                    table.assign_cell(
                        || "assign board coordinate cell",
                        self.coordinates,
                        i,
                        || Value::known(F::from(placements[0][i] as u64))
                    )?;
                    table.assign_cell(
                        || "assign board value cell",
                        self.coordinates,
                        i,
                        || Value::known(F::from(placements[1][i] as u64))
                    )?;
                }
                Ok(())
            },
        )
    }
}

