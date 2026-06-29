use crate::{Ciphertext, PrivateKey, PublicKey, Trapdoor, generate_trapdoor, encrypt};
use ark_ec::hashing::HashToCurveError;
use crate::helper::{NameParseError, parse_name};


#[derive(Debug)]
pub enum NameError {
    Parse(NameParseError),
    Hash(HashToCurveError),
}

pub struct NameTrapdoor {
    pub components: Vec<Trapdoor>,
}

pub struct NameCiphertext {
    pub components: Vec<Ciphertext>,
}

impl NameTrapdoor{
    pub fn sort_key(&self) -> Vec<u8> {
        self.components.iter().flat_map(|t| t.to_bytes()).collect()
    }
}

pub fn name_to_trapdoor(
    private_key: &PrivateKey,
    name: &str,
) -> Result<NameTrapdoor, NameError>{
    let components = parse_name(name).map_err(  NameError::Parse)?;
    let mut trapdoors = Vec::new();
    for component in components {
        let trapdoor = generate_trapdoor(private_key, component.as_bytes())
            .map_err(NameError::Hash)?;
        trapdoors.push(trapdoor);
    }
    Ok(NameTrapdoor { components: trapdoors })
}

pub fn name_to_ciphertext(
    public_key: &PublicKey,
    name: &str,
) -> Result<NameCiphertext, NameError> {
    let components = parse_name(name).map_err(NameError::Parse)?;
    let mut ciphertexts = Vec::new();
    for component in components {
        let ciphertext = encrypt(public_key, component.as_bytes())
            .map_err(NameError::Hash)?;
        ciphertexts.push(ciphertext);
    }
    Ok(NameCiphertext { components: ciphertexts })
}

#[cfg(test)]
mod name_to_trapdoor_test {
    use super::*;
    use crate::generate_key_pair;

    #[test]
    fn name_to_trapdoor_produces_correct_number_of_components() {
        let (private_key, _ ) = generate_key_pair();
        let result = name_to_trapdoor(&private_key, "/ndn/peks/test").unwrap();
        assert_eq!(result.components.len(), 3);
    }

    #[test]
    fn name_to_trapdoor_is_deterministic() {
        let (private_key, _ ) = generate_key_pair();
        let result1 = name_to_trapdoor(&private_key, "/ndn/peks/test").unwrap();
        let result2 = name_to_trapdoor(&private_key, "/ndn/peks/test").unwrap();
        // Each component's trapdoor should be the same for the same input
        for (t1, t2) in result1.components.iter().zip(result2.components.iter()) {
            assert_eq!(t1.t, t2.t);
        }
    }

    #[test]
    fn name_to_ciphertext_is_probabilistic () {
        let (_, public_key) = generate_key_pair();
        let result1 = name_to_ciphertext(&public_key, "/ndn/peks/test").unwrap();
        let result2 = name_to_ciphertext(&public_key, "/ndn/peks/test").unwrap();
        // Each component should differ (probabilistic)

        for (t1, t2) in result1.components.iter().zip(result2.components.iter()) {
            assert! (t1.a != t2.a);
        }
    }

    #[test]
    fn name_with_malformed_input_return_error() {
        let (private_key, _ ) = generate_key_pair();
        assert!(matches! (name_to_trapdoor(&private_key, "abc/no/slash"), Err(NameError::Parse(NameParseError::MissingLeadingSlash))));
        
    }

    #[test]
    fn name_to_ciphertext_rejects_empty_name (){
        let (_, public_key) = generate_key_pair();
        assert!(matches!(
            name_to_ciphertext(&public_key, ""), 
            Err(NameError::Parse(NameParseError::Empty))
        ));
    }

    #[test]
    fn sort_key_is_deterministic(){
        let(private_key, _) = generate_key_pair();
        let nt1 = name_to_trapdoor(&private_key, "/ndn/test/peks").unwrap();
        let nt2 = name_to_trapdoor(&private_key, "/ndn/test/peks").unwrap();
        assert_eq!(nt1.sort_key(), nt2.sort_key());
    }

    #[test]
    fn sort_keys_with_shared_name_prefix_share_byte_prefix() {
        let (private_key, _) = generate_key_pair();
        let nt1 = name_to_trapdoor(&private_key, "/a/b/c").unwrap();
        let nt2 = name_to_trapdoor(&private_key, "/a/b/d").unwrap();
    
        // Both names start with /a/b. Their sort keys should share the first 2*48 = 96 bytes.
        let shared_bytes = nt1.sort_key().iter()
            .zip(nt2.sort_key().iter())
            .take_while(|(a, b)| a == b)
            .count();
    
        assert!(shared_bytes >= 96, 
            "Expected at least 96 shared bytes (2 trapdoors x 48 bytes), got {}", 
            shared_bytes);
    }
}