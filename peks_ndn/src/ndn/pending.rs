//! Pending interest tracker.
//!
//! When an interest arrives at a router, a hash of the interest URI is
//! computed and stored together with the URI itself. When the producer
//! later disseminates a trapdoor update that includes this hash, the
//! router uses the hash to recover the original interest URI, so it can
//! pair the incoming trapdoor with the correct pending interest.
//!
//! This bridges a mismatch in the PEKS-NDN protocol: interest names are
//! probabilistic (different bytes for each request), while trapdoor
//! updates use deterministic trapdoors. The hash acts as a "receipt"
//! that links a specific request to its trapdoor update response.

use std::collections::HashMap;
use sha2::{Sha256, Digest};


pub struct PendingInterests {
    entries: HashMap<Vec<u8>, String>,
}


impl PendingInterests {
    pub fn new() -> Self {
        PendingInterests { entries: HashMap::new() }
    }

    /// Compute SHA-256 of the URI, store the (hash, URI) pair, and return
    /// the hash bytes so the caller can propagate them (for example, by
    /// forwarding to the producer, who will echo the hash in the trapdoor
    /// update response).
    pub fn insert(&mut self, uri: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(uri.as_bytes());
        let hash = hasher.finalize().to_vec();
        self.entries.insert(hash.clone(), uri.to_string());
        hash
    }

    /// Look up an interest URI by its hash and remove the entry.
    /// Returns None if no matching entry exists.
    pub fn lookup_and_remove(&mut self, hash: &[u8]) -> Option<String> {
        self.entries.remove(hash)
    }

    /// Check whether a hash is currently tracked, without removing it.
    pub fn contains(&self, hash: &[u8]) -> bool {
        self.entries.contains_key(hash)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}


impl Default for PendingInterests {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_then_lookup_returns_original_uri() {
        let mut pending = PendingInterests::new();
        let uri = "/peks_strategy/some_ciphertext";
        let hash = pending.insert(uri);
        let recovered = pending.lookup_and_remove(&hash);
        assert_eq!(recovered, Some(uri.to_string()));
    }

    #[test]
    fn lookup_removes_entry() {
        let mut pending = PendingInterests::new();
        let uri = "/peks_strategy/some_ciphertext";
        let hash = pending.insert(uri);

        // First lookup succeeds
        assert!(pending.lookup_and_remove(&hash).is_some());
        // Second lookup on same hash returns None (entry was removed)
        assert!(pending.lookup_and_remove(&hash).is_none());
    }

    #[test]
    fn different_uris_produce_different_hashes() {
        let mut pending = PendingInterests::new();
        let hash1 = pending.insert("/peks_strategy/uri_one");
        let hash2 = pending.insert("/peks_strategy/uri_two");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn same_uri_produces_same_hash() {
        let mut p1 = PendingInterests::new();
        let mut p2 = PendingInterests::new();
        let uri = "/peks_strategy/same_uri";
        let hash1 = p1.insert(uri);
        let hash2 = p2.insert(uri);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn lookup_of_unknown_hash_returns_none() {
        let mut pending = PendingInterests::new();
        let fake_hash = vec![0u8; 32];
        assert!(pending.lookup_and_remove(&fake_hash).is_none());
    }

    #[test]
    fn contains_reports_presence_without_removing() {
        let mut pending = PendingInterests::new();
        let uri = "/peks_strategy/some_uri";
        let hash = pending.insert(uri);

        assert!(pending.contains(&hash));
        assert!(pending.contains(&hash));  // still there after check
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn length_tracking() {
        let mut pending = PendingInterests::new();
        assert_eq!(pending.len(), 0);
        assert!(pending.is_empty());

        pending.insert("/peks_strategy/a");
        pending.insert("/peks_strategy/b");
        pending.insert("/peks_strategy/c");
        assert_eq!(pending.len(), 3);
        assert!(!pending.is_empty());

        // Remove one
        let hash = {
            let mut h = Sha256::new();
            h.update(b"/peks_strategy/a");
            h.finalize().to_vec()
        };
        pending.lookup_and_remove(&hash);
        assert_eq!(pending.len(), 2);

    }
}