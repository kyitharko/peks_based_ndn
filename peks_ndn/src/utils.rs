use ark_bls12_381::Fr;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;

pub fn generate_random() -> Fr {
    let mut rng = thread_rng();
    Fr::rand(&mut rng)
}
