use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ark_serialize::SerializationError;

use crate::{Ciphertext, Trapdoor};
use crate::ndn::name::{NameCiphertext, NameTrapdoor};

const PEKS_STRATEGY_PREFIX: &str = "/peks_strategy/";
const TRAPDOOR_MARKER: &str = "Tw";
const TRAPDOOR_REG_MARKER: &str = "TwReg";


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
    let rest = uri.strip_prefix(PEKS_STRATEGY_PREFIX)
        .ok_or(WireError::MissingPeksStrategyPrefix)?;

    let raw_components: Vec<&str> = rest.split('/').collect();

    if raw_components.is_empty() || (raw_components.len() == 1 && raw_components[0].is_empty()) {
        return Err(WireError::Empty);
    }

    // Ciphertext URI must not start with either trapdoor marker
    if raw_components[0] == TRAPDOOR_MARKER || raw_components[0] == TRAPDOOR_REG_MARKER {
        return Err(WireError::UnexpectedTrapdoorMarker);
    }

    let mut ciphertexts = Vec::new();
    for comp in raw_components {
        if comp.is_empty() {
            continue;
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
// Trapdoor name (utility — not part of the protocol flow)
// -----------------------------------------------------------------------------

/// Encode a NameTrapdoor into a URI: /peks_strategy/Tw/<TN1>/.../<TNk>
///
/// This is a utility function. The actual protocol uses either
/// `encode_trapdoor_registration` (for the producer's prefix, at setup)
/// or `encode_trapdoor_update` (for reactive dissemination with a hash).
pub fn encode_trapdoor_name(nt: &NameTrapdoor) -> String {
    let components: Vec<String> = nt.components.iter()
        .map(|t| URL_SAFE_NO_PAD.encode(t.to_bytes()))
        .collect();
    format!("{}{}/{}", PEKS_STRATEGY_PREFIX, TRAPDOOR_MARKER, components.join("/"))
}

/// Decode a trapdoor URI back into a NameTrapdoor (utility, non-protocol).
pub fn decode_trapdoor_name(uri: &str) -> Result<NameTrapdoor, WireError> {
    let rest = uri.strip_prefix(PEKS_STRATEGY_PREFIX)
        .ok_or(WireError::MissingPeksStrategyPrefix)?;

    let raw_components: Vec<&str> = rest.split('/').collect();

    if raw_components.is_empty() || raw_components[0].is_empty() {
        return Err(WireError::Empty);
    }

    if raw_components[0] != TRAPDOOR_MARKER {
        return Err(WireError::MissingTrapdoorMarker);
    }

    let mut trapdoors = Vec::new();
    for comp in &raw_components[1..] {
        if comp.is_empty() {
            continue;
        }
        let bytes = URL_SAFE_NO_PAD.decode(*comp)
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
// Trapdoor prefix registration (protocol: setup phase)
// -----------------------------------------------------------------------------

/// Encode a single prefix trapdoor as a registration URI:
/// /peks_strategy/TwReg/<prefix_trapdoor>
///
/// Sent by the producer once during setup to register its prefix trapdoor
/// with the network. Routers use this to populate their trapdoor tables
/// with the producer's prefix (for longest-prefix-match forwarding).
pub fn encode_trapdoor_registration(prefix_trapdoor: &Trapdoor) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(prefix_trapdoor.to_bytes());
    format!("{}{}/{}", PEKS_STRATEGY_PREFIX, TRAPDOOR_REG_MARKER, encoded)
}

/// Decode a trapdoor registration URI back into a single Trapdoor.
pub fn decode_trapdoor_registration(uri: &str) -> Result<Trapdoor, WireError> {
    let rest = uri.strip_prefix(PEKS_STRATEGY_PREFIX)
        .ok_or(WireError::MissingPeksStrategyPrefix)?;

    let raw_components: Vec<&str> = rest.split('/').collect();

    if raw_components.is_empty() || raw_components[0].is_empty() {
        return Err(WireError::Empty);
    }

    if raw_components[0] != TRAPDOOR_REG_MARKER {
        return Err(WireError::MissingTrapdoorMarker);
    }

    // Filter empties, then require exactly one trapdoor component
    let trapdoor_components: Vec<&&str> = raw_components[1..].iter()
        .filter(|c| !c.is_empty())
        .collect();

    if trapdoor_components.len() != 1 {
        return Err(WireError::Empty);
    }

    let bytes = URL_SAFE_NO_PAD.decode(*trapdoor_components[0])
        .map_err(WireError::Base64Decode)?;
    let trapdoor = Trapdoor::from_bytes(&bytes)
        .map_err(WireError::Deserialization)?;

    Ok(trapdoor)
}


// -----------------------------------------------------------------------------
// Reactive trapdoor update (protocol: response to interest)
// -----------------------------------------------------------------------------

/// Encode a NameTrapdoor plus a SHA-256 hash into a trapdoor update URI:
/// /peks_strategy/Tw/<TN1>/.../<TNk>/<hash>
///
/// Sent by the producer as a response to a specific interest, after the
/// data packet has been delivered. The hash is SHA-256 of the original
/// interest URI. Routers use the hash to look up the pending interest and
/// pair this trapdoor sequence with the data packet that arrived earlier.
pub fn encode_trapdoor_update(nt: &NameTrapdoor, hash: &[u8]) -> String {
    let trapdoor_components: Vec<String> = nt.components.iter()
        .map(|t| URL_SAFE_NO_PAD.encode(t.to_bytes()))
        .collect();
    let hash_component = URL_SAFE_NO_PAD.encode(hash);
    format!(
        "{}{}/{}/{}",
        PEKS_STRATEGY_PREFIX,
        TRAPDOOR_MARKER,
        trapdoor_components.join("/"),
        hash_component,
    )
}

/// Decode a trapdoor update URI into (NameTrapdoor, hash bytes).
/// The last component is treated as the hash; all others as trapdoors.
/// Requires at least one trapdoor component plus the hash.
pub fn decode_trapdoor_update(uri: &str) -> Result<(NameTrapdoor, Vec<u8>), WireError> {
    let rest = uri.strip_prefix(PEKS_STRATEGY_PREFIX)
        .ok_or(WireError::MissingPeksStrategyPrefix)?;

    let raw_components: Vec<&str> = rest.split('/').collect();

    if raw_components.is_empty() || raw_components[0].is_empty() {
        return Err(WireError::Empty);
    }

    if raw_components[0] != TRAPDOOR_MARKER {
        return Err(WireError::MissingTrapdoorMarker);
    }

    // Filter out empty components after the marker
    let non_empty: Vec<&str> = raw_components[1..].iter()
        .filter(|c| !c.is_empty())
        .copied()
        .collect();

    // Need at least one trapdoor + one hash
    if non_empty.len() < 2 {
        return Err(WireError::Empty);
    }

    let trapdoor_slices = &non_empty[..non_empty.len() - 1];
    let hash_slice = non_empty[non_empty.len() - 1];

    let mut trapdoors = Vec::new();
    for comp in trapdoor_slices {
        let bytes = URL_SAFE_NO_PAD.decode(*comp)
            .map_err(WireError::Base64Decode)?;
        let td = Trapdoor::from_bytes(&bytes)
            .map_err(WireError::Deserialization)?;
        trapdoors.push(td);
    }

    let hash = URL_SAFE_NO_PAD.decode(hash_slice)
        .map_err(WireError::Base64Decode)?;

    Ok((NameTrapdoor { components: trapdoors }, hash))
}


// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_key_pair;
    use crate::ndn::name::{name_to_ciphertext, name_to_trapdoor};

    // -----------------------------------------------------------------------
    // Ciphertext name tests
    // -----------------------------------------------------------------------

    #[test]
    fn ciphertext_name_encode_starts_with_peks_strategy() {
        let (_, public_key) = generate_key_pair();
        let nc = name_to_ciphertext(&public_key, "/alice/bob/charlie").unwrap();
        let uri = encode_ciphertext_name(&nc);
        assert!(uri.starts_with("/peks_strategy/"));
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
    fn decode_ciphertext_rejects_missing_peks_prefix() {
        let result = decode_ciphertext_name("/other_strategy/foo/bar");
        assert!(matches!(result, Err(WireError::MissingPeksStrategyPrefix)));
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

    // -----------------------------------------------------------------------
    // Trapdoor name tests (utility functions)
    // -----------------------------------------------------------------------

    #[test]
    fn trapdoor_name_encode_contains_tw_marker() {
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/alice/bob/charlie").unwrap();
        let uri = encode_trapdoor_name(&nt);
        assert!(uri.starts_with("/peks_strategy/Tw/"));
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
    fn decode_trapdoor_rejects_missing_tw_marker() {
        let (_, public_key) = generate_key_pair();
        let nc = name_to_ciphertext(&public_key, "/alice/bob").unwrap();
        let ciphertext_uri = encode_ciphertext_name(&nc);
        let result = decode_trapdoor_name(&ciphertext_uri);
        assert!(matches!(result, Err(WireError::MissingTrapdoorMarker)));
    }

    // -----------------------------------------------------------------------
    // Trapdoor registration tests
    // -----------------------------------------------------------------------

    #[test]
    fn trapdoor_registration_encode_uses_twreg_marker() {
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/producer").unwrap();
        let prefix_trapdoor = &nt.components[0];
        let uri = encode_trapdoor_registration(prefix_trapdoor);
        assert!(uri.starts_with("/peks_strategy/TwReg/"));
    }

    #[test]
    fn trapdoor_registration_round_trip() {
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/producer").unwrap();
        let original = &nt.components[0];
        let uri = encode_trapdoor_registration(original);
        let recovered = decode_trapdoor_registration(&uri).unwrap();
        assert_eq!(original.t, recovered.t);
    }

    #[test]
    fn decode_trapdoor_registration_rejects_missing_prefix() {
        let result = decode_trapdoor_registration("/other/TwReg/abc");
        assert!(matches!(result, Err(WireError::MissingPeksStrategyPrefix)));
    }

    #[test]
    fn decode_trapdoor_registration_rejects_wrong_marker() {
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/producer").unwrap();
        let uri = encode_trapdoor_update(&nt, &vec![0u8; 32]);
        let result = decode_trapdoor_registration(&uri);
        assert!(matches!(result, Err(WireError::MissingTrapdoorMarker)));
    }

    #[test]
    fn decode_trapdoor_registration_rejects_empty() {
        let result = decode_trapdoor_registration("/peks_strategy/TwReg/");
        assert!(matches!(result, Err(WireError::Empty)));
    }

    #[test]
    fn decode_trapdoor_registration_rejects_multiple_components() {
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/producer/alice").unwrap();
        let t1_encoded = URL_SAFE_NO_PAD.encode(nt.components[0].to_bytes());
        let t2_encoded = URL_SAFE_NO_PAD.encode(nt.components[1].to_bytes());
        let uri = format!("/peks_strategy/TwReg/{}/{}", t1_encoded, t2_encoded);
        let result = decode_trapdoor_registration(&uri);
        assert!(matches!(result, Err(WireError::Empty)));
    }

    // -----------------------------------------------------------------------
    // Trapdoor update tests
    // -----------------------------------------------------------------------

    #[test]
    fn trapdoor_update_encode_uses_tw_marker() {
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/producer/alice").unwrap();
        let hash = vec![0xABu8; 32];
        let uri = encode_trapdoor_update(&nt, &hash);
        assert!(uri.starts_with("/peks_strategy/Tw/"));
        assert!(!uri.starts_with("/peks_strategy/TwReg/"));
    }

    #[test]
    fn trapdoor_update_round_trip() {
        let (private_key, _) = generate_key_pair();
        let original_nt = name_to_trapdoor(&private_key, "/producer/alice/profile").unwrap();
        let original_hash = vec![0x42u8; 32];

        let uri = encode_trapdoor_update(&original_nt, &original_hash);
        let (recovered_nt, recovered_hash) = decode_trapdoor_update(&uri).unwrap();

        assert_eq!(original_nt.components.len(), recovered_nt.components.len());
        for (orig, rec) in original_nt.components.iter().zip(recovered_nt.components.iter()) {
            assert_eq!(orig.t, rec.t);
        }
        assert_eq!(original_hash, recovered_hash);
    }

    #[test]
    fn decode_trapdoor_update_rejects_missing_prefix() {
        let result = decode_trapdoor_update("/other/Tw/abc/def");
        assert!(matches!(result, Err(WireError::MissingPeksStrategyPrefix)));
    }

    #[test]
    fn decode_trapdoor_update_rejects_missing_marker() {
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/producer").unwrap();
        let reg_uri = encode_trapdoor_registration(&nt.components[0]);
        let result = decode_trapdoor_update(&reg_uri);
        assert!(matches!(result, Err(WireError::MissingTrapdoorMarker)));
    }

    #[test]
    fn decode_trapdoor_update_rejects_too_few_components() {
        let result = decode_trapdoor_update("/peks_strategy/Tw/");
        assert!(matches!(result, Err(WireError::Empty)));

        let hash_component = URL_SAFE_NO_PAD.encode(vec![0u8; 32]);
        let uri = format!("/peks_strategy/Tw/{}", hash_component);
        let result = decode_trapdoor_update(&uri);
        assert!(matches!(result, Err(WireError::Empty)));
    }

    // -----------------------------------------------------------------------
    // Cross-format rejection tests
    // -----------------------------------------------------------------------

    #[test]
    fn ciphertext_decoder_rejects_trapdoor_reg_uri() {
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/producer").unwrap();
        let reg_uri = encode_trapdoor_registration(&nt.components[0]);
        let result = decode_ciphertext_name(&reg_uri);
        assert!(matches!(result, Err(WireError::UnexpectedTrapdoorMarker)));
    }

    #[test]
    fn ciphertext_decoder_rejects_trapdoor_update_uri() {
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/producer/alice").unwrap();
        let update_uri = encode_trapdoor_update(&nt, &vec![0u8; 32]);
        let result = decode_ciphertext_name(&update_uri);
        assert!(matches!(result, Err(WireError::UnexpectedTrapdoorMarker)));
    }

    #[test]
    fn ciphertext_decoder_rejects_trapdoor_name_uri() {
        let (private_key, _) = generate_key_pair();
        let nt = name_to_trapdoor(&private_key, "/alice/bob").unwrap();
        let trapdoor_uri = encode_trapdoor_name(&nt);
        let result = decode_ciphertext_name(&trapdoor_uri);
        assert!(matches!(result, Err(WireError::UnexpectedTrapdoorMarker)));
    }
}