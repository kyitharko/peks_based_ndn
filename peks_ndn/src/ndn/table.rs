use crate::ndn::name::NameTrapdoor;
use crate::Trapdoor;


pub struct TrapdoorTableEntry {
    pub trapdoors: Vec<Trapdoor>,
    pub sort_key: Vec<u8>,
    pub cleartext_name: Option <String>,
}


pub struct TrapdoorTable {
    entries: Vec<TrapdoorTableEntry>,
}

pub struct MatchResult {
    pub exact_match: Option<usize>,        // row index of exact match, or None
    pub longest_prefix: Option<(usize, usize)>,  // (row index, match length), or None
}


impl TrapdoorTable{
    pub fn match_naive(&self, ciphertext: &[Ciphertext]) -> MatchResult {
        let mut exact_match = None;
        let mut longest_prefix: Option<(usize, usize)> = None;
        
        for (row_idx, entry) in self.entries.iter().enumerate() {
            // Walk component by component, counting matches until first mismatch
            let mut match_length = 0;
            for i in 0..ciphertext.len() {
                if i >= entry.trapdoors.len() {
                    break;  // ran out of trapdoors in this row
                }
                if test(&entry.trapdoors[i], &ciphertext[i]) {
                    match_length += 1;
                } else {
                    break;  // first mismatch, stop testing this row
                }
            }
            
            // Was this an exact match?
            // (every ciphertext component matched, and the row has exactly that many trapdoors)
            if match_length == ciphertext.len() && match_length == entry.trapdoors.len() {
                exact_match = Some(row_idx);
            }
            
            // Did this row produce the longest prefix so far?
            let current_best = longest_prefix.map(|(_, len)| len).unwrap_or(0);
            if match_length > current_best {
                longest_prefix = Some((row_idx, match_length));
            }
        }
        
        MatchResult { exact_match, longest_prefix }
    }

    pub fn new() -> Self {
        TrapdoorTable{ entries: Vec::new() }
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
}

 #[cfg(test)]
    mod tests {
        use super::*;
        use crate::generate_key_pair;
        use crate::ndn::name::name_to_trapdoor;
    
        #[test]
        fn insert_keeps_table_sorted() {
            let (private_key, _) = generate_key_pair();
            let mut table = TrapdoorTable::new();
        
               // Insert in unsorted order
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
        
            // Verify entries are sorted by sort_key
            for i in 1..table.entries.len() {
                assert!(table.entries[i-1].sort_key <= table.entries[i].sort_key);
            }
        }
    }