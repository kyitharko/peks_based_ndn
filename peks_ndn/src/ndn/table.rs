use crate::{Trapdoor, Ciphertext};
use crate::peks::test;
use crate::ndn::name::NameTrapdoor;


pub struct TrapdoorTableEntry {
    pub trapdoors: Vec<Trapdoor>,
    pub sort_key: Vec<u8>,
    pub cleartext_name: Option<String>,
}


pub struct TrapdoorTable {
    entries: Vec<TrapdoorTableEntry>,
}

pub struct MatchResult {
    pub exact_match: Option<usize>,
    pub longest_prefix: Option<(usize, usize)>,
}


impl TrapdoorTable {
    pub fn new() -> Self {
        TrapdoorTable { entries: Vec::new() }
    }

    pub fn insert(&mut self, name_trapdoor: NameTrapdoor, cleartext_name: Option<String>) {
        let sort_key = name_trapdoor.sort_key();
        let entry = TrapdoorTableEntry {
            trapdoors: name_trapdoor.components,
            sort_key,
            cleartext_name,
        };

        let pos = self.entries
            .binary_search_by(|e| e.sort_key.cmp(&entry.sort_key))
            .unwrap_or_else(|p| p);
        self.entries.insert(pos, entry);
    }

    /// Exhaustive-search matching, faithful to Algorithm 1 of the paper.
    /// Walks every row, tests every component from position 0 until first mismatch.
    pub fn match_exhaustive(&self, ciphertext: &[Ciphertext]) -> MatchResult {
        let mut exact_match = None;
        let mut longest_prefix: Option<(usize, usize)> = None;
        
        for (row_idx, entry) in self.entries.iter().enumerate() {
            let mut match_length = 0;
            for i in 0..ciphertext.len() {
                if i >= entry.trapdoors.len() {
                    break;
                }
                if test(&entry.trapdoors[i], &ciphertext[i]) {
                    match_length += 1;
                } else {
                    break;
                }
            }
            
            if match_length == ciphertext.len() && match_length == entry.trapdoors.len() {
                exact_match = Some(row_idx);
                break;  // per paper: return immediately on exact match
            }
            
            let current_best = longest_prefix.map(|(_, len)| len).unwrap_or(0);
            if match_length > current_best {
                longest_prefix = Some((row_idx, match_length));
            }
        }
        
        MatchResult { exact_match, longest_prefix }
    }

    /// Return the trapdoor sequence at the given row index, or None if the
    /// index is out of bounds.
    pub fn get_trapdoors(&self, row: usize) -> Option<&[Trapdoor]> {
        self.entries.get(row).map(|e| e.trapdoors.as_slice())
    }

    /// Return the cleartext name at the given row index, if one is stored
    /// (producer-side entries have Some, router-side entries have None).
    /// Returns None if the index is out of bounds or the row has no
    /// cleartext name attached.
    pub fn get_cleartext_name(&self, row: usize) -> Option<&str> {
        self.entries.get(row).and_then(|e| e.cleartext_name.as_deref())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_key_pair;
    use crate::ndn::name::{name_to_trapdoor, name_to_ciphertext};

    #[test]
    fn insert_keeps_table_sorted() {
        let (private_key, _) = generate_key_pair();
        let mut table = TrapdoorTable::new();
    
        table.insert(
            name_to_trapdoor(&private_key, "/a/b/c").unwrap(),
            Some("/a/b/c".to_string()),
        );
        table.insert(
            name_to_trapdoor(&private_key, "/a/b/a").unwrap(),
            Some("/a/b/a".to_string()),
        );
        table.insert(
            name_to_trapdoor(&private_key, "/a/b/e").unwrap(),
            Some("/a/b/e".to_string()),
        );
    
        for i in 1..table.entries.len() {
            assert!(table.entries[i-1].sort_key <= table.entries[i].sort_key);
        }
    }

    #[test]
    fn match_exhaustive_finds_exact_match() {
        let (private_key, public_key) = generate_key_pair();
        let mut table = TrapdoorTable::new();
        
        table.insert(
            name_to_trapdoor(&private_key, "/a/b/c").unwrap(),
            Some("/a/b/c".to_string()),
        );
        
        let ct = name_to_ciphertext(&public_key, "/a/b/c").unwrap();
        let result = table.match_exhaustive(&ct.components);
        
        assert_eq!(result.exact_match, Some(0));
    }
    
    #[test]
    fn match_exhaustive_finds_longest_prefix_when_no_exact_match() {
        let (private_key, public_key) = generate_key_pair();
        let mut table = TrapdoorTable::new();
        
        table.insert(
            name_to_trapdoor(&private_key, "/a/b/c").unwrap(),
            Some("/a/b/c".to_string()),
        );
        
        let ct = name_to_ciphertext(&public_key, "/a/b/d").unwrap();
        let result = table.match_exhaustive(&ct.components);
        
        assert_eq!(result.exact_match, None);
        assert_eq!(result.longest_prefix, Some((0, 2)));
    }
    
    #[test]
    fn match_exhaustive_returns_none_when_no_match() {
        let (private_key, public_key) = generate_key_pair();
        let mut table = TrapdoorTable::new();
        
        table.insert(
            name_to_trapdoor(&private_key, "/a/b/c").unwrap(),
            Some("/a/b/c".to_string()),
        );
        
        let ct = name_to_ciphertext(&public_key, "/x/y/z").unwrap();
        let result = table.match_exhaustive(&ct.components);
        
        assert_eq!(result.exact_match, None);
        assert_eq!(result.longest_prefix, None);
    }

    #[test]
    fn get_trapdoors_returns_row_contents() {
        let (private_key, _) = generate_key_pair();
        let mut table = TrapdoorTable::new();
        let nt = name_to_trapdoor(&private_key, "/a/b/c").unwrap();
        let original_trapdoors = nt.components.clone();
        table.insert(nt, Some("/a/b/c".to_string()));

        let retrieved = table.get_trapdoors(0).unwrap();
        assert_eq!(retrieved.len(), 3);
        // Compare each trapdoor's serialized bytes to confirm they match
        for (orig, ret) in original_trapdoors.iter().zip(retrieved.iter()) {
            assert_eq!(orig.to_bytes(), ret.to_bytes());
        }
    }

    #[test]
    fn get_trapdoors_out_of_bounds_returns_none() {
        let table = TrapdoorTable::new();
        assert!(table.get_trapdoors(0).is_none());
        assert!(table.get_trapdoors(100).is_none());
    }

    #[test]
    fn get_cleartext_name_returns_stored_name() {
        let (private_key, _) = generate_key_pair();
        let mut table = TrapdoorTable::new();
        table.insert(
            name_to_trapdoor(&private_key, "/producer/alice").unwrap(),
            Some("/producer/alice".to_string()),
        );

        assert_eq!(table.get_cleartext_name(0), Some("/producer/alice"));
    }

    #[test]
    fn get_cleartext_name_returns_none_when_no_name_stored() {
        let (private_key, _) = generate_key_pair();
        let mut table = TrapdoorTable::new();
        // Insert without cleartext name — this is the router-side case
        table.insert(
            name_to_trapdoor(&private_key, "/producer/alice").unwrap(),
            None,
        );

        assert!(table.get_cleartext_name(0).is_none());
    }

    #[test]
    fn get_cleartext_name_out_of_bounds_returns_none() {
        let table = TrapdoorTable::new();
        assert!(table.get_cleartext_name(0).is_none());
    }
}