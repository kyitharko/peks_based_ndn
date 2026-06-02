
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

pub struct KeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
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
        let mut _private_key = PrivateKey { alpha: generate_random() };
        let _generator = G2Projective::generator();
        let mut _public_key = PublicKey {
            h: _generator * _private_key.alpha,
        };
        let _key_pair = KeyPair {
            private_key: _private_key,
            public_key: _public_key,
        };
        assert!(_key_pair.private_key.alpha != Fr::ZERO);
        assert!(_key_pair.public_key.h != G2Projective::ZERO);
        let generator = G2Projective::generator();
        let expected_h: G2Projective = generator * _key_pair.private_key.alpha;
        assert!(expected_h == _key_pair.public_key.h);
    }
}
