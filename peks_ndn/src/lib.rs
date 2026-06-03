
use ark_bls12_381::{Fr, G1Projective, g1, G2Projective};
use ark_ec::{PrimeGroup, AdditiveGroup, hashing::curve_maps::wb::WBMap, 
    hashing::HashToCurve, hashing::HashToCurveError, 
    hashing::map_to_curve_hasher::MapToCurveBasedHasher};
use ark_ff::fields::field_hashers::DefaultFieldHasher;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use sha2::Sha256;

pub struct PublicKey {
    pub h: G2Projective,
}

pub struct PrivateKey {
    pub alpha: Fr,
}


pub fn hash_to_g1(keyword: &[u8]) -> Result<G1Projective, HashToCurveError> {
    let dst = b"PEKS-NDN_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    let mapper = MapToCurveBasedHasher::
        <G1Projective,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<ark_bls12_381::g1::Config>,
    >::new(dst).unwrap();
    let point  = mapper.hash(keyword)?;
    Ok(G1Projective::from(point))
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
        // let (private_key, public_key) = generate_key_pair();
        // assert!(private_key.alpha != Fr::ZERO);
        // assert!(public_key.h != G2Projective::ZERO);
        // let generator = G2Projective::generator();
        // let expected_h: G2Projective = generator * private_key.alpha;
        // assert!(expected_h == public_key.h);
        let mut _point1 : G1Projective = G1Projective::default();
        let mut _point2 : G1Projective = G1Projective::default();
        match hash_to_g1(b"test") {
            Ok(_point1) => println!("Success! Point generated safely. {:?}", _point1    ),
            Err(error) => println!("Failed to generate point: {:?}", error),
        }

        match hash_to_g1(b"test") {
            Ok(_point2) => println!("Success! Point generated safely. {:?}", _point2),
            Err(error) => println!("Failed to generate point: {:?}", error),
        }
        assert!(_point1 == _point2);
    }
}
