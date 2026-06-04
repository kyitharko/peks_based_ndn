
use ark_bls12_381::{Fr, G1Projective, g1, G2Projective, Bls12_381};
use ark_ec::{PrimeGroup, AdditiveGroup, hashing::curve_maps::wb::WBMap, 
    hashing::HashToCurve, hashing::HashToCurveError, 
    hashing::map_to_curve_hasher::MapToCurveBasedHasher, pairing::Pairing};
use ark_ff::fields::field_hashers::DefaultFieldHasher;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use ark_serialize::{CanonicalSerialize};
use sha2::{Sha256, digest::Digest};

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

pub fn encrypt(public_key: &PublicKey, keyword: &[u8]) -> Result<Ciphertext, HashToCurveError>{
    let r = generate_random();
    let a = G2Projective::generator() * r;
    let h_r = public_key.h * r;
    let h1_w = hash_to_g1(keyword)?;
    let pairing_output = Bls12_381::pairing(h1_w, h_r);
    let mut bytes = Vec::new();
    pairing_output.serialize_uncompressed(&mut bytes).unwrap();
    let b: [u8; 32] = Sha256::digest(&bytes).into();
    Ok(Ciphertext { a, b })
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
    use ark_ec::AdditiveGroup;  // for ZERO constants
    
    #[test]
    fn keygen_produces_consistent_keypair() {
        let (private_key, public_key) = generate_key_pair();
        assert!(private_key.alpha != Fr::ZERO);
        assert!(public_key.h != G2Projective::ZERO);
        let generator = G2Projective::generator();
        let expected_h = generator * private_key.alpha;
        assert_eq!(public_key.h, expected_h);
    }
    
    #[test]
    fn hash_to_g1_is_deterministic() {
        let point1 = hash_to_g1(b"alice").unwrap();
        let point2 = hash_to_g1(b"alice").unwrap();
        assert_eq!(point1, point2);
    }
    
    #[test]
    fn hash_to_g1_produces_non_identity() {
        let point = hash_to_g1(b"alice").unwrap();
        assert!(point != G1Projective::ZERO);
    }
    
    #[test]
    fn hash_to_g1_different_inputs_give_different_outputs() {
        let point1 = hash_to_g1(b"alice").unwrap();
        let point2 = hash_to_g1(b"bob").unwrap();
        assert!(point1 != point2);
    }
    #[test]
    fn encrypt_produces_non_trivial_output() {
    let (_, public_key) = generate_key_pair();
    let ciphertext = encrypt(&public_key, b"alice").unwrap();
    assert!(ciphertext.a != G2Projective::ZERO);
    assert!(ciphertext.b != [0u8; 32]);
    }

    #[test]
    fn encrypt_is_probabilistic() {
    let (_, public_key) = generate_key_pair();
    let ct1 = encrypt(&public_key, b"alice").unwrap();
    let ct2 = encrypt(&public_key, b"alice").unwrap();
    assert!(ct1.a != ct2.a);
    assert!(ct1.b != ct2.b);
    }
    
    #[test]
    fn encrypt_distinguishes_keywords() {
    let (_, public_key) = generate_key_pair();
    let ct1 = encrypt(&public_key, b"alice").unwrap();
    let ct2 = encrypt(&public_key, b"bob").unwrap();
    assert!(ct1.a != ct2.a || ct1.b != ct2.b);
    }

}