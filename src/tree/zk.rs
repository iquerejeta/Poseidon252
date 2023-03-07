// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::PoseidonBranch;
use hades::GadgetStrategy;

use plonk::prelude::*;

/// Perform a merkle opening for a given branch and return the calculated root
pub fn merkle_opening<C, const DEPTH: usize>(
    composer: &mut C,
    branch: &PoseidonBranch<DEPTH>,
    leaf: Witness,
) -> Witness
where
    C: Composer,
{
    // Generate a permutation container
    let mut container = [C::ZERO; hades::WIDTH];

    // Recalculate the root for the given branch
    (0..DEPTH).fold(leaf, |root, depth| {
        let level = branch.as_ref()[depth];

        // Create the bits representation of the offset as witness
        // and make sure that offset points to a hash in the level
        let offset_flag = level.offset_flag();
        let mut sum = C::ZERO;
        let mut offset_bits = [C::ZERO; hades::WIDTH - 1];
        offset_bits.iter_mut().fold(1, |mask, bit| {
            let bit_bls = BlsScalar::from((offset_flag & mask).min(1));
            *bit = composer.append_witness(bit_bls);

            let constraint = Constraint::new().left(1).a(sum).right(1).b(*bit);
            sum = composer.gate_add(constraint);

            mask << 1
        });
        composer.assert_equal_constant(sum, BlsScalar::one(), None);

        // Check that the root of the previous level is the same value as what
        // is stored in the level at the offset
        for i in 0..hades::WIDTH {
            // Load child hashes of the current level into the permutation
            // container
            container[i] = composer.append_witness(level.as_ref()[i]);
            if i > 0 {
                let bit = offset_bits[i - 1];

                // `expected` and `calculated` will be zero everywhere except
                // at the level offset
                let constraint =
                    Constraint::new().mult(1).a(bit).b(container[i]);
                let expected = composer.gate_mul(constraint);
                let constraint = Constraint::new().mult(1).a(bit).b(root);
                let calculated = composer.gate_mul(constraint);

                // Make sure that the hash at the offset of the current level
                // matches the hash calculated in the previous level
                composer.assert_equal(expected, calculated);
            }
        }

        // Calculate the root for the next level
        GadgetStrategy::gadget(composer, &mut container);
        container[1]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use plonk::error::Error as PlonkError;
    use nstack::annotation::Keyed;
    use rand::rngs::OsRng;
    use rand::rngs::StdRng;
    use rand::{CryptoRng, RngCore, SeedableRng};

    use crate::tree::{self, PoseidonLeaf, PoseidonTree};

    const DEPTH: usize = 17;
    const CAPACITY: usize = 15;
    type Tree = PoseidonTree<MockLeaf, u64, DEPTH>;

    #[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
    struct MockLeaf {
        s: BlsScalar,
        pub pos: u64,
    }

    impl Keyed<u64> for MockLeaf {
        fn key(&self) -> &u64 {
            &self.pos
        }
    }

    impl MockLeaf {
        pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
            let s = BlsScalar::random(rng);
            let pos = 0;

            Self { s, pos }
        }
    }

    impl From<u64> for MockLeaf {
        fn from(n: u64) -> MockLeaf {
            MockLeaf {
                s: BlsScalar::from(n),
                pos: 0,
            }
        }
    }

    impl PoseidonLeaf for MockLeaf {
        fn poseidon_hash(&self) -> BlsScalar {
            self.s
        }

        fn pos(&self) -> &u64 {
            &self.pos
        }

        fn set_pos(&mut self, pos: u64) {
            self.pos = pos;
        }
    }

    #[derive(Default)]
    struct MerkleOpeningCircuit {
        pub branch: PoseidonBranch<DEPTH>,
    }

    impl MerkleOpeningCircuit {
        pub fn random<R: RngCore + CryptoRng>(
            rng: &mut R,
            tree: &mut Tree,
        ) -> Self {
            let leaf = MockLeaf::random(rng);
            let pos = tree.push(leaf);

            let branch = tree.branch(pos).expect(
                "Failed to fetch the branch of the created leaf from the tree",
            );

            Self { branch }
        }
    }

    impl Circuit for MerkleOpeningCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), PlonkError>
        where
            C: Composer,
        {
            let leaf: BlsScalar = *self.branch;
            let leaf = composer.append_witness(leaf);

            let root = self.branch.root();
            let root = composer.append_witness(*root);

            let root_p =
                tree::merkle_opening::<C, DEPTH>(composer, &self.branch, leaf);

            composer.assert_equal(root_p, root);

            Ok(())
        }
    }

    fn init_valid_opening_setup() -> (
        Prover<MerkleOpeningCircuit>,
        Verifier<MerkleOpeningCircuit>,
        MerkleOpeningCircuit,
    ) {
        let label = b"dusk-network";
        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

        let (prover, verifier) =
            Compiler::compile(&pp, label).expect("failed to compile circuit");

        let mut tree = Tree::default();
        let circuit = MerkleOpeningCircuit::random(&mut OsRng, &mut tree);

        (prover, verifier, circuit)
    }

    #[test]
    fn merkle_opening() {
        let (prover, verifier, circuit) = init_valid_opening_setup();
        let mut rng = StdRng::seed_from_u64(0xbeef);

        let (proof, public_inputs) = prover
            .prove(&mut rng, &circuit)
            .expect("proving the circuit should succeed");

        verifier
            .verify(&proof, &public_inputs)
            .expect("verifying the proof should succeed");
    }

    #[test]
    fn merkle_opening_invalid_hash() {
        let (prover, _, mut circuit) = init_valid_opening_setup();
        let mut rng = StdRng::seed_from_u64(0xfeeb);

        circuit.branch.path[3].level[3] = BlsScalar::random(&mut OsRng);

        // With an incorrect path we can not generate a valid proof
        prover
            .prove(&mut rng, &circuit)
            .expect_err("Proof generation should fail");
    }

    #[test]
    fn merkle_opening_invalid_path() {
        let (prover, _, mut circuit) = init_valid_opening_setup();
        let mut rng = StdRng::seed_from_u64(0xfeeb);

        for depth in 0..DEPTH {
            for offset in 1..hades::WIDTH {
                circuit.branch.path[depth].level[offset] =
                    BlsScalar::random(&mut OsRng);
            }
        }

        // With an incorrect path we can not generate a valid proof
        prover
            .prove(&mut rng, &circuit)
            .expect_err("Proof generation should fail");
    }
}
