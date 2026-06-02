
use ark_bls12_381::Fr;
use ark_bls12_381::G2Projective;
use ark_ec::PrimeGroup;
use ark_std::rand::thread_rng;
use ark_ff::fields::AdditiveGroup;
use ark_std::UniformRand;

pub struct PublicKey {
    pub h: G2Projective,
}

pub struct PrivateKey {
    pub alpha: Fr,
}


pub fn generate_key_pair() -> (PrivateKey, PublicKey) {
    let private_key = PrivateKey { alpha: generate_random() };
    let generator = G2Projective::generator();
    let public_key = PublicKey {
        h: generator * private_key.alpha,
    };
    (private_key, public_key)
}
pub fn generate_random() -> Fr {
    let mut rng = thread_rng();
    Fr::rand(&mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let (private_key, public_key) = generate_key_pair();
        assert!(private_key.alpha != Fr::ZERO);
        assert!(public_key.h != G2Projective::ZERO);
        let generator = G2Projective::generator();
        let expected_h: G2Projective = generator * private_key.alpha;
        assert!(expected_h == public_key.h);
    }
}
