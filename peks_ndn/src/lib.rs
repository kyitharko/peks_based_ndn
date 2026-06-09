use ark_bls12_381::{Fr, G1Projective, G2Projective};


pub struct PublicKey {
    pub h: G2Projective,
}

pub struct PrivateKey {
    pub alpha: Fr,
}

pub struct Ciphertext {
    pub a: G2Projective,
    pub b: [u8; 32],
}

pub struct Trapdoor {
    pub t: G1Projective,
}

pub mod peks;
pub mod hash;
mod utils;

pub use peks::{generate_key_pair, encrypt, generate_trapdoor, test};
pub use hash::hash_to_g1;