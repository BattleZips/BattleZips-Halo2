/*

    1, 1, 2, 3, 5, 8, 13, ...

    | elem_1 | elem_2 | sum | q_fib
    --------------------------------
    |    1   |    1   |  2  |   1
    |    1   |    2   |  3  |   1
    |    2   |    3   |  5  |   1
    |        |        |     |   0

    q_fib * (elem_1 + elem_2 - elem_3) = 0

*/

use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;
use halo2_gadgets::sinsemilla;


#[derive(Clone, Debug, Copy)]
struct Config {
    ship_x: Column<Advice>,
    ship_y: Column<Advice>,
    ship_z: Column<Advice>,
    hash: Column<Instance>,
    hash_selector: Selector,
}

impl Config {
    fn configure<F: Field>(cs: &mut ConstraintSystem<F>) -> Self {
        let ship_x = cs.advice_column();
        cs.enable_equality(ship_x);
        let ship_y = cs.advice_column();
        cs.enable_equality(ship_y);
        let ship_z = cs.advice_column();
        cs.enable_equality(ship_z);
        let hash_selector = cs.selector();

        cs.create_gate("")

        // cs.create_gate("fibonacci", |virtual_cells| {
        //     let q_fib = virtual_cells.query_selector(q_fib);
        //     let elem_1 = virtual_cells.query_advice(elem_1, Rotation::cur());
        //     let elem_2 = virtual_cells.query_advice(elem_2, Rotation::cur());
        //     let elem_3 = virtual_cells.query_advice(elem_3, Rotation::cur());

        //     vec![
        //         //     q_fib * (elem_1 + elem_2 - elem_3) = 0
        //         q_fib * (elem_1 + elem_2 - elem_3),
        //     ]
        // });

        // Self {
        //     elem_1,
        //     elem_2,
        //     elem_3,
        //     q_fib,
        // }
    }

    fn alloc_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
    
    }

    fn init<F: Field>(
        &self,
        mut layouter: impl Layouter<F>,
        elem_1: Value<F>,
        elem_2: Value<F>,
    ) -> Result<
        (
            AssignedCell<F, F>, // elem_2
            AssignedCell<F, F>, // elem_3
        ),
        Error,
    > {
        layouter.assign_region(
            || "init Fibonacci",
            |mut region| {
                let offset = 0;

                // Enable q_fib
                self.q_fib.enable(&mut region, offset)?;

                // Assign elem_1
                region.assign_advice(|| "elem_1", self.elem_1, offset, || elem_1)?;

                // Assign elem_2
                let elem_2 = region.assign_advice(|| "elem_2", self.elem_2, offset, || elem_2)?;

                let elem_3 = elem_1 + elem_2.value_field().evaluate();
                // Assign elem_3
                let elem_3 = region.assign_advice(|| "elem_3", self.elem_3, offset, || elem_3)?;

                Ok((elem_2, elem_3))
            },
        )
    }

    fn assign<F: Field>(
        &self,
        mut layouter: impl Layouter<F>,
        elem_2: AssignedCell<F, F>,
        elem_3: AssignedCell<F, F>,
    ) -> Result<
        (
            AssignedCell<F, F>, // elem_2
            AssignedCell<F, F>, // elem_3
        ),
        Error,
    > {
        layouter.assign_region(
            || "steady-state Fibonacci",
            |mut region| {
                let offset = 0;

                // Enable q_fib
                self.q_fib.enable(&mut region, offset)?;

                // Copy elem_1 (which is the previous elem_2)
                let elem_1 = elem_2.copy_advice(
                    || "copy elem_2 into current elem_1",
                    &mut region,
                    self.elem_1,
                    offset,
                )?;

                // Copy elem_2 (which is the previous elem_3)
                let elem_2 = elem_3.copy_advice(
                    || "copy elem_3 into current elem_2",
                    &mut region,
                    self.elem_2,
                    offset,
                )?;

                let elem_3 = elem_1.value_field().evaluate() + elem_2.value_field().evaluate();
                // Assign elem_3
                let elem_3 = region.assign_advice(|| "elem_3", self.elem_3, offset, || elem_3)?;

                Ok((elem_2, elem_3))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, pasta::Fp};

    use super::*;


    */

    #[derive(Default)]
    struct MyCircuit<F: Field> {
        elem_1: Value<F>, // 1
        elem_2: Value<F>, // 1
    }

    impl<F: Field> Circuit<F> for MyCircuit<F> {
        type Config = Config;

        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            Self::Config::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // elem_2 = 1, elem_3 = 2
            let (elem_2, elem_3) =
                config.init(layouter.namespace(|| "init"), self.elem_1, self.elem_2)?;
            // 1 + 2 = 3
            config.assign(
                layouter.namespace(|| "first assign after init"),
                elem_2,
                elem_3,
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_fib() {
        let circuit = MyCircuit {
            elem_1: Value::known(Fp::one()),
            elem_2: Value::known(Fp::one()),
        };

        let prover = MockProver::run(3, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
