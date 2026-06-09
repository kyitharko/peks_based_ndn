use ark_ec::{hashing::{HashToCurve, HashToCurveError, map_to_curve_hasher::MapToCurveBasedHasher, curve_maps::wb::WBMap}};
use ark_bls12_381::G1Projective;
use ark_ff::fields::field_hashers::DefaultFieldHasher;
use sha2::Sha256;


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


#[cfg(test)]
mod hash_to_g1_test {
    use super::*;
    use ark_ec::AdditiveGroup;  // for ZERO constant

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
}