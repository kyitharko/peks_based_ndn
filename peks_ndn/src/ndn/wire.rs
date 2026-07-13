use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ark_serialize::SerializationError;

use crate::{Ciphertext, Trapdoor};
use crate::ndn::name::{NameCiphertext, NameTrapdoor};

const PEKS_STRATEGY_PREFIX: &str = "/peks_strategy/";
const TRAPDOOR_MARKER: &str = "Tw";


#[derive(Debug)]
pub enum WireError {
    MissingPeksStrategyPrefix,
    MissingTrapdoorMarker,
    UnexpectedTrapdoorMarker,
    Empty,
    Base64Decode(base64::DecodeError),
    Deserialization(SerializationError),
}


// -----------------------------------------------------------------------------
// Ciphertext name
// -----------------------------------------------------------------------------

/// Encode a NameCiphertext into an NDN URI: /peks_strategy/<C1>/.../<Ck>
pub fn encode_ciphertext_name(nc: &NameCiphertext) -> String {
    let components: Vec<String> = nc.components.iter()
        .map(|c| URL_SAFE_NO_PAD.encode(c.to_bytes()))
        .collect();
    format!("{}{}", PEKS_STRATEGY_PREFIX, components.join("/"))
}

/// Decode a ciphertext URI back into a NameCiphertext.
pub fn decode_ciphertext_name(uri: &str) -> Result<NameCiphertext, WireError> {
    // Strip /peks_strategy/ prefix
    let rest = uri.strip_prefix(PEKS_STRATEGY_PREFIX)
        .ok_or(WireError::MissingPeksStrategyPrefix)?;
    
    // Split remaining into components
    let raw_components: Vec<&str> = rest.split('/').collect();
    
    if raw_components.is_empty() || (raw_components.len() == 1 && raw_components[0].is_empty()) {
        return Err(WireError::Empty);
    }
    
    // Ciphertext URI should NOT have the Tw marker
    if raw_components[0] == TRAPDOOR_MARKER {
        return Err(WireError::UnexpectedTrapdoorMarker);
    }
    
    // Base64 decode each component, then deserialize to Ciphertext
    let mut ciphertexts = Vec::new();
    for comp in raw_components {
        if comp.is_empty() {
            continue;  // skip empty from doubled slashes
        }
        let bytes = URL_SAFE_NO_PAD.decode(comp)
            .map_err(WireError::Base64Decode)?;
        let ct = Ciphertext::from_bytes(&bytes)
            .map_err(WireError::Deserialization)?;
        ciphertexts.push(ct);
    }
    
    if ciphertexts.is_empty() {
        return Err(WireError::Empty);
    }
    
    Ok(NameCiphertext { components: ciphertexts })
}


// -----------------------------------------------------------------------------
// Trapdoor name
// -----------------------------------------------------------------------------

/// Encode a NameTrapdoor into an NDN URI: /peks_strategy/Tw/<TN1>/.../<TNk>
pub fn encode_trapdoor_name(nt: &NameTrapdoor) -> String {
    let components: Vec<String> = nt.components.iter()
        .map(|t| URL_SAFE_NO_PAD.encode(t.to_bytes()))
        .collect();
    format!("{}{}/{}", PEKS_STRATEGY_PREFIX, TRAPDOOR_MARKER, components.join("/"))
}

/// Decode a trapdoor URI back into a NameTrapdoor.
pub fn decode_trapdoor_name(uri: &str) -> Result<NameTrapdoor, WireError> {
    // Strip /peks_strategy/ prefix
    let rest = uri.strip_prefix(PEKS_STRATEGY_PREFIX)
        .ok_or(WireError::MissingPeksStrategyPrefix)?;
    
    let raw_components: Vec<&str> = rest.split('/').collect();
    
    if raw_components.is_empty() || raw_components[0].is_empty() {
        return Err(WireError::Empty);
    }
    
    // First component MUST be the trapdoor marker
    if raw_components[0] != TRAPDOOR_MARKER {
        return Err(WireError::MissingTrapdoorMarker);
    }
    
    // Skip the marker; decode the rest
    let mut trapdoors = Vec::new();
    for comp in &raw_components[1..] {
        if comp.is_empty() {
            continue;
        }
        let bytes = URL_SAFE_NO_PAD.decode(comp)
            .map_err(WireError::Base64Decode)?;
        let td = Trapdoor::from_bytes(&bytes)
            .map_err(WireError::Deserialization)?;
        trapdoors.push(td);
    }
    
    if trapdoors.is_empty() {
        return Err(WireError::Empty);
    }
    
    Ok(NameTrapdoor { components: trapdoors })
}


// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_key_pair;
    use crate::ndn::name::{name_to_ciphertext, name_to_trapdoor};

    #[test]
    fn ciphertext_name_encode_starts_with_peks_strategy() {
        let (_, public_key) = generate_key_pair();
        let nc = name_to_ciphertext(&public_key, "/alice/bob/charlie").unwrap();
        let uri = encode_ciphertext_name(&nc);
        assert!(uri.starts_with("/peks_strategy/"));
    }

    #[test]
    fn trapdoor_name_encode_contains_tw_marker() {
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/alice/bob/charlie").unwrap();
        let uri = encode_trapdoor_name(&nt);
        assert!(uri.starts_with("/peks_strategy/Tw/"));
    }

    #[test]
    fn ciphertext_name_round_trip() {
        let (_, public_key) = generate_key_pair();
        let original = name_to_ciphertext(&public_key, "/alice/bob/charlie").unwrap();
        let uri = encode_ciphertext_name(&original);
        let recovered = decode_ciphertext_name(&uri).unwrap();
        
        assert_eq!(original.components.len(), recovered.components.len());
        for (o, r) in original.components.iter().zip(recovered.components.iter()) {
            assert_eq!(o.a, r.a);
            assert_eq!(o.b, r.b);
        }
    }

    #[test]
    fn trapdoor_name_round_trip() {
        let (private_key, _) = generate_key_pair();
        let original = name_to_trapdoor(&private_key, "/alice/bob/charlie").unwrap();
        let uri = encode_trapdoor_name(&original);
        let recovered = decode_trapdoor_name(&uri).unwrap();
        
        assert_eq!(original.components.len(), recovered.components.len());
        for (o, r) in original.components.iter().zip(recovered.components.iter()) {
            assert_eq!(o.t, r.t);
        }
    }

    #[test]
    fn decode_ciphertext_rejects_missing_peks_prefix() {
        let result = decode_ciphertext_name("/other_strategy/foo/bar");
        assert!(matches!(result, Err(WireError::MissingPeksStrategyPrefix)));
    }

    #[test]
    fn decode_ciphertext_rejects_tw_marker() {
        // A trapdoor URI should not decode as a ciphertext URI
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/alice/bob").unwrap();
        let trapdoor_uri = encode_trapdoor_name(&nt);
        let result = decode_ciphertext_name(&trapdoor_uri);
        assert!(matches!(result, Err(WireError::UnexpectedTrapdoorMarker)));
    }

    #[test]
    fn decode_trapdoor_rejects_missing_tw_marker() {
        // A ciphertext URI should not decode as a trapdoor URI
        let (_, public_key) = generate_key_pair();
        let nc = name_to_ciphertext(&public_key, "/alice/bob").unwrap();
        let ciphertext_uri = encode_ciphertext_name(&nc);
        let result = decode_trapdoor_name(&ciphertext_uri);
        assert!(matches!(result, Err(WireError::MissingTrapdoorMarker)));
    }
    
    #[test]
    fn decode_ciphertext_rejects_empty() {
        let result = decode_ciphertext_name("/peks_strategy/");
        assert!(matches!(result, Err(WireError::Empty)));
    }
    
    #[test]
    fn decode_ciphertext_rejects_invalid_base64() {
        let result = decode_ciphertext_name("/peks_strategy/@@@invalid@@@");
        assert!(matches!(result, Err(WireError::Base64Decode(_))));
    }
}