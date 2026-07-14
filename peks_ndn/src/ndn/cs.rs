//! PEKS Content Store.
//!
//! A cache mapping trapdoor sequences to data packets. Because PEKS
//! ciphertexts are probabilistic, we cannot use NDN's built-in name-keyed
//! CS — every request for the same content produces a different interest
//! name. The PEKS CS is keyed by trapdoor sequences instead, which are
//! deterministic for the same content name.
//!
//! Populated reactively: when a producer disseminates a trapdoor update,
//! the router pairs the incoming trapdoor sequence with the previously
//! received data packet and inserts the (trapdoors, data) pair here.
//! Subsequent requests for the same content produce different ciphertexts
//! but match the same trapdoor sequence, so the router can serve them
//! from cache without re-querying the producer.

use std::collections::HashMap;

use crate::Trapdoor;


/// Minimal data packet for the PEKS-NDN reimplementation.
///
/// Real NDN Data packets include signatures, metadata, and encoding rules
/// defined in the NDN packet format specification. For the reimplementation,
/// we only need the cleartext name and the content payload.
pub struct DataPacket {
    pub name: String,
    pub content: Vec<u8>,
}


pub struct PeksCS {
    entries: HashMap<Vec<u8>, DataPacket>,
}


impl PeksCS {
    pub fn new() -> Self {
        PeksCS { entries: HashMap::new() }
    }

    /// Insert a data packet keyed by the given trapdoor sequence.
    /// If an entry already exists for this sequence, it is overwritten.
    pub fn insert(&mut self, trapdoors: &[Trapdoor], data: DataPacket) {
        let key = trapdoors_to_key(trapdoors);
        self.entries.insert(key, data);
    }

    /// Look up a data packet by trapdoor sequence.
    /// Returns None if no matching entry exists.
    pub fn lookup(&self, trapdoors: &[Trapdoor]) -> Option<&DataPacket> {
        let key = trapdoors_to_key(trapdoors);
        self.entries.get(&key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}


impl Default for PeksCS {
    fn default() -> Self {
        Self::new()
    }
}


/// Compute a stable byte key for a trapdoor sequence by serializing each
/// trapdoor and concatenating the bytes. Two sequences produce equal keys
/// if and only if the trapdoors are pairwise equal (since serialization
/// is deterministic).
fn trapdoors_to_key(trapdoors: &[Trapdoor]) -> Vec<u8> {
    trapdoors.iter().flat_map(|t| t.to_bytes()).collect()
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_key_pair;
    use crate::ndn::name::name_to_trapdoor;

    fn make_data(name: &str, content: &[u8]) -> DataPacket {
        DataPacket {
            name: name.to_string(),
            content: content.to_vec(),
        }
    }

    #[test]
    fn insert_then_lookup_returns_data() {
        let (private_key, _) = generate_key_pair();
        let mut cs = PeksCS::new();
        let nt = name_to_trapdoor(&private_key, "/producer/alice/profile").unwrap();
        let data = make_data("/producer/alice/profile", b"Hello");

        cs.insert(&nt.components, data);
        let found = cs.lookup(&nt.components);

        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.name, "/producer/alice/profile");
        assert_eq!(found.content, b"Hello");
    }

    #[test]
    fn lookup_of_different_trapdoors_returns_none() {
        let (private_key, _) = generate_key_pair();
        let mut cs = PeksCS::new();
        let nt_stored = name_to_trapdoor(&private_key, "/producer/alice/profile").unwrap();
        let nt_query = name_to_trapdoor(&private_key, "/producer/bob/profile").unwrap();

        cs.insert(&nt_stored.components, make_data("/producer/alice/profile", b"Hello"));

        assert!(cs.lookup(&nt_query.components).is_none());
    }

    #[test]
    fn insert_overwrites_existing_entry() {
        let (private_key, _) = generate_key_pair();
        let mut cs = PeksCS::new();
        let nt = name_to_trapdoor(&private_key, "/producer/alice/profile").unwrap();

        cs.insert(&nt.components, make_data("/producer/alice/profile", b"first"));
        cs.insert(&nt.components, make_data("/producer/alice/profile", b"second"));

        let found = cs.lookup(&nt.components).unwrap();
        assert_eq!(found.content, b"second");
        // Length is still 1 — same key, replaced value
        assert_eq!(cs.len(), 1);
    }

    #[test]
    fn empty_cs_returns_none_for_any_lookup() {
        let (private_key, _) = generate_key_pair();
        let cs = PeksCS::new();
        let nt = name_to_trapdoor(&private_key, "/anything").unwrap();

        assert!(cs.lookup(&nt.components).is_none());
        assert!(cs.is_empty());
    }

    #[test]
    fn length_tracking() {
        let (private_key, _) = generate_key_pair();
        let mut cs = PeksCS::new();

        assert_eq!(cs.len(), 0);
        assert!(cs.is_empty());

        let nt1 = name_to_trapdoor(&private_key, "/a/b/c").unwrap();
        let nt2 = name_to_trapdoor(&private_key, "/x/y/z").unwrap();

        cs.insert(&nt1.components, make_data("/a/b/c", b"one"));
        cs.insert(&nt2.components, make_data("/x/y/z", b"two"));

        assert_eq!(cs.len(), 2);
        assert!(!cs.is_empty());
    }

    #[test]
    fn same_name_from_same_key_produces_same_lookup() {
        // Sanity check: name_to_trapdoor is deterministic, so producing
        // the trapdoor sequence twice for the same name gives the same key.
        let (private_key, _) = generate_key_pair();
        let mut cs = PeksCS::new();

        let nt_stored = name_to_trapdoor(&private_key, "/producer/data").unwrap();
        cs.insert(&nt_stored.components, make_data("/producer/data", b"content"));

        // A separate call produces an equivalent NameTrapdoor.
        let nt_query = name_to_trapdoor(&private_key, "/producer/data").unwrap();
        let found = cs.lookup(&nt_query.components);

        assert!(found.is_some());
        assert_eq!(found.unwrap().content, b"content");
    }
}