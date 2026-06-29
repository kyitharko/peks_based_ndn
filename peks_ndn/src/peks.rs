use crate::{PublicKey, PrivateKey, Ciphertext, Trapdoor};
use crate::utils::generate_random;
use crate::hash::hash_to_g1;


use ark_ec::{hashing::HashToCurveError, PrimeGroup, pairing::Pairing};
use ark_bls12_381::{G1Projective, G2Projective, Bls12_381};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};
use sha2::{Sha256, digest::Digest};


impl Trapdoor {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.t.serialize_compressed(&mut bytes).unwrap();
        bytes
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let point = G1Projective::deserialize_compressed(bytes)?;
        Ok(Trapdoor { t: point })
    }
}

impl Ciphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.a.serialize_compressed(&mut bytes).unwrap();
        bytes.extend_from_slice(&self.b);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        // Compressed G2 element on BLS12-381 is 96 bytes, 
        const G2_SIZE: usize = 96;

        if bytes.len() != G2_SIZE + 32 {
            return Err(SerializationError::InvalidData);
        }
        let a = G2Projective::deserialize_compressed(&bytes[..G2_SIZE])?;
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes[G2_SIZE..]);
        Ok(Ciphertext {a, b})
    }
}

pub fn generate_key_pair() -> (PrivateKey, PublicKey) {
    let private_key = PrivateKey { alpha: generate_random() };
    let generator = G2Projective::generator();
    let public_key = PublicKey {
        h: generator * private_key.alpha,
    };
    (private_key, public_key)
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


pub fn generate_trapdoor(private_key: &PrivateKey, keyword: &[u8]) -> Result<Trapdoor, HashToCurveError> {
    let h1_w = hash_to_g1(keyword)?;
    let t = h1_w * private_key.alpha;
    Ok(Trapdoor {t})
}


pub fn test(trapdoor: &Trapdoor, ciphertext: &Ciphertext) -> bool {
    let pairing_left = Bls12_381::pairing(trapdoor.t, ciphertext.a);
    let mut bytes = Vec::new();
    pairing_left.serialize_uncompressed(&mut bytes).unwrap();
    let hash_left: [u8; 32] = Sha256::digest(&bytes).into();
    hash_left == ciphertext.b
}


#[cfg(test)]
mod keygen_test {
    use super::*;
    use ark_ec::AdditiveGroup;  // for ZERO constants
    use ark_bls12_381::Fr;  // for ZERO constant

    #[test]
    fn keygen_produces_consistent_keypair() {
        let (private_key, public_key) = generate_key_pair();
        assert!(private_key.alpha != Fr::ZERO);
        assert!(public_key.h != G2Projective::ZERO);
        let generator = G2Projective::generator();
        let expected_h = generator * private_key.alpha;
        assert_eq!(public_key.h, expected_h);
    }
}

#[cfg(test)]
mod peks_test {
    use super::*;
    use ark_ec::AdditiveGroup;  // for ZERO constants

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


    #[test]
    fn cipher_text_round_trip() {
        let (_, public_key) = generate_key_pair();
        let original = encrypt(&public_key, b"alice").unwrap();
        let bytes = original.to_bytes();
        let recovered = Ciphertext::from_bytes(&bytes).unwrap();
    
    
        // Verify a was correctly serialized and deserialized
        assert_eq!(original.a, recovered.a);
    
        // Verify b was correctly serialized and deserialized
        assert_eq!(original.b, recovered.b);
    }

    #[test]
    fn ciphertext_from_bytes_rejects_wrong_length() {
        let result = Ciphertext::from_bytes(&[0u8; 50]); // wrong size
        assert!(result.is_err());
    }
}


#[cfg(test)]
mod trapdoor_test {
    use super::*;
    #[test]
    fn trapdoor_is_deterministic() {
        let (private_key, _) = generate_key_pair();
        let trapdoor1 = generate_trapdoor(&private_key, b"alice").unwrap();
        let trapdoor2 = generate_trapdoor(&private_key, b"alice").unwrap();
        assert_eq!(trapdoor1.t, trapdoor2.t);
    }

    #[test]
    fn trapdoor_different_keywords() {
        let (private_key, _) = generate_key_pair();
        let trapdoor1 = generate_trapdoor(&private_key, b"alice").unwrap();
        let trapdoor2 = generate_trapdoor(&private_key, b"bob").unwrap();
        assert!(trapdoor1.t != trapdoor2.t);
    }

    #[test]
    fn different_trapdoors_different_key_same_keyword() {
        let (private_key1, _) = generate_key_pair();
        let (private_key2, _) = generate_key_pair();
        let trapdoor1 = generate_trapdoor(&private_key1, b"alice").unwrap();
        let trapdoor2 = generate_trapdoor(&private_key2, b"alice").unwrap();
        assert!(trapdoor1.t != trapdoor2.t);
    }
    #[test]
    fn trapdoor_serialization_is_deterministic() {
        let (private_key, _) = generate_key_pair();
        let t1 = generate_trapdoor(&private_key, b"alice").unwrap();
        let t2 = generate_trapdoor(&private_key, b"alice").unwrap();
        assert_eq!(t1.to_bytes(), t2.to_bytes());
    }
    
    #[test]
    fn different_trapdoors_have_different_bytes() {
        let (private_key, _) = generate_key_pair();
        let t1 = generate_trapdoor(&private_key, b"alice").unwrap();
        let t2 = generate_trapdoor(&private_key, b"bob").unwrap();
        assert!(t1.to_bytes() != t2.to_bytes());
    }

    #[test]
    fn trapdoor_round_trip() {
        let (private_key, _) = generate_key_pair();
        let original = generate_trapdoor(&private_key, b"alice").unwrap();
        let bytes = original.to_bytes();
        let recovered = Trapdoor::from_bytes(&bytes).unwrap();
        assert_eq!(original.t, recovered.t);
    }

    
}

#[cfg(test)]
mod peks_operation_test {
    use super::*;
     #[test]
    fn peks_round_trip_succeeds_for_matching_keyword() {
        let (private_key, public_key) = generate_key_pair();
        let keyword = b"alice";
        let trapdoor = generate_trapdoor(&private_key, keyword).unwrap();
        let ciphertext = encrypt(&public_key, keyword).unwrap();
        assert!(test(&trapdoor, &ciphertext));
    }
    #[test]
    fn peks_round_trip_fails_for_non_matching_keyword() {
        let (private_key, public_key) = generate_key_pair();
        let trapdoor = generate_trapdoor(&private_key, b"alice").unwrap();
        let ciphertext = encrypt(&public_key, b"bob").unwrap();
        assert!(!test(&trapdoor, &ciphertext));
    }
    #[test]
    fn peks_handles_multiple_encryptions_of_same_keyword() {
    let (private_key, public_key) = generate_key_pair();
    let trapdoor_alice = generate_trapdoor(&private_key, b"alice").unwrap();
    let ct1 = encrypt(&public_key, b"alice").unwrap();
    let ct2 = encrypt(&public_key, b"alice").unwrap();
    assert!(ct1.a != ct2.a);  // probabilistic
    assert!(test(&trapdoor_alice, &ct1));  // both match the same trapdoor
    assert!(test(&trapdoor_alice, &ct2));
    }
    
}

