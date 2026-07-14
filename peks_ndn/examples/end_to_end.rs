//! End-to-end PEKS-NDN demonstration.
//!
//! Simulates a small network with one producer, one router, and one consumer.
//! The consumer reads a list of names from a file and makes random requests.
//! Metrics are collected: cache hit ratio and total pairing operations.
//!
//! Protocol flow:
//! 1. Producer generates keys, populates its trapdoor table and content storage.
//! 2. Producer sends TwReg URI for its prefix. Router stores prefix trapdoor.
//! 3. Consumer picks a random name and creates an encrypted interest.
//! 4. Router receives interest:
//!    - Records (hash, uri) in pending tracker.
//!    - Matches against trapdoor table.
//!    - If cache hit, returns cached data.
//!    - If cache miss, forwards to producer.
//! 5. Producer receives interest, matches, returns data.
//! 6. Router receives data, stores in staged storage.
//! 7. Producer sends trapdoor update. Router pairs with staged data, updates CS.
//!
//! Run with: cargo run --release --example end_to_end

use std::collections::HashMap;
use std::fs;
use std::time::Instant;

use rand::seq::SliceRandom;
use rand::thread_rng;

use peks_ndn::{
    generate_key_pair, PrivateKey, PublicKey,
};
use peks_ndn::ndn::name::{name_to_ciphertext, name_to_trapdoor};
use peks_ndn::ndn::table::TrapdoorTable;
use peks_ndn::ndn::cs::{PeksCS, DataPacket};
use peks_ndn::ndn::pending::PendingInterests;
use peks_ndn::ndn::wire::{
    encode_ciphertext_name,
    decode_ciphertext_name,
    encode_trapdoor_registration,
    decode_trapdoor_registration,
    encode_trapdoor_update,
    decode_trapdoor_update,
};

const NUM_REQUESTS: usize = 50;
const NAMES_FILE: &str = "examples/names.txt";


// -----------------------------------------------------------------------------
// Producer
// -----------------------------------------------------------------------------

struct Producer {
    private_key: PrivateKey,
    public_key: PublicKey,
    prefix: String,
    trapdoor_table: TrapdoorTable,
    // Maps cleartext name to the data content the producer serves.
    content: HashMap<String, Vec<u8>>,
}

impl Producer {
    fn new(prefix: &str) -> Self {
        let (private_key, public_key) = generate_key_pair();
        Producer {
            private_key,
            public_key,
            prefix: prefix.to_string(),
            trapdoor_table: TrapdoorTable::new(),
            content: HashMap::new(),
        }
    }

    /// Register a content name with associated data. Populates producer's
    /// own trapdoor table so it can match incoming interests.
    fn register_content(&mut self, name: &str, data: Vec<u8>) {
        let nt = name_to_trapdoor(&self.private_key, name).unwrap();
        self.trapdoor_table.insert(nt, Some(name.to_string()));
        self.content.insert(name.to_string(), data);
    }

    /// Produce the TwReg URI for the producer's prefix, used at setup to
    /// register the prefix with routers.
    fn prefix_registration_uri(&self) -> String {
        let prefix_with_slash = format!("/{}", self.prefix);
        let nt = name_to_trapdoor(&self.private_key, &prefix_with_slash).unwrap();
        encode_trapdoor_registration(&nt.components[0])
    }

    /// Handle an incoming interest URI. Returns (DataPacket, trapdoor_update_uri).
    /// The trapdoor update includes the hash from the router so the router
    /// can pair the trapdoor with the data it has staged.
    fn on_interest(&self, uri: &str, interest_hash: &[u8]) -> Option<(DataPacket, String)> {
        let nc = decode_ciphertext_name(uri).ok()?;
        let match_result = self.trapdoor_table.match_exhaustive(&nc.components);

        let row = match_result.exact_match?;
        let cleartext_name = self.trapdoor_table.get_cleartext_name(row)?;
        let data_bytes = self.content.get(cleartext_name)?;

        let data = DataPacket {
            name: cleartext_name.to_string(),
            content: data_bytes.clone(),
        };

        // Produce the trapdoor update URI for the router to update its CS.
        let nt = name_to_trapdoor(&self.private_key, cleartext_name).unwrap();
        let update_uri = encode_trapdoor_update(&nt, interest_hash);

        Some((data, update_uri))
    }
}


// -----------------------------------------------------------------------------
// Router
// -----------------------------------------------------------------------------

struct Router {
    trapdoor_table: TrapdoorTable,
    cs: PeksCS,
    pending: PendingInterests,
    // Temporary storage for data packets awaiting trapdoor update.
    // Keyed by interest hash. Removed after CS is updated.
    staged_data: HashMap<Vec<u8>, DataPacket>,
    // Counters for metrics
    cache_hits: usize,
    cache_misses: usize,
}

impl Router {
    fn new() -> Self {
        Router {
            trapdoor_table: TrapdoorTable::new(),
            cs: PeksCS::new(),
            pending: PendingInterests::new(),
            staged_data: HashMap::new(),
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Receive a TwReg URI and store the prefix trapdoor in the table.
    fn on_trapdoor_registration(&mut self, uri: &str) {
        let prefix_trapdoor = decode_trapdoor_registration(uri)
            .expect("router received malformed TwReg URI");
        // Insert as a single-component NameTrapdoor with no cleartext name.
        // In real deployment, this would also register the ingress face in FIB.
        let nt = peks_ndn::ndn::name::NameTrapdoor {
            components: vec![prefix_trapdoor],
        };
        self.trapdoor_table.insert(nt, None);
    }

    /// Handle an incoming interest URI from a consumer.
    /// Returns Some(DataPacket) if served from cache, None if forwarded upstream.
    ///
    /// If None, the caller should forward the interest to the producer and
    /// then call on_data() with the returned data packet and on_trapdoor_update()
    /// with the trapdoor update URI.
    fn on_interest(&mut self, uri: &str) -> ForwardDecision {
        // Track this interest as pending
        let hash = self.pending.insert(uri);

        // Decode the ciphertext
        let nc = match decode_ciphertext_name(uri) {
            Ok(nc) => nc,
            Err(_) => return ForwardDecision::Drop,
        };

        // Match against trapdoor table
        let match_result = self.trapdoor_table.match_exhaustive(&nc.components);

        // If exact match, check CS
        if let Some(row) = match_result.exact_match {
            if let Some(trapdoors) = self.trapdoor_table.get_trapdoors(row) {
                if let Some(data) = self.cs.lookup(trapdoors) {
                    // Cache hit
                    self.cache_hits += 1;
                    // Remove from pending since we're serving directly
                    self.pending.lookup_and_remove(&hash);
                    return ForwardDecision::ServeFromCache(DataPacket {
                        name: data.name.clone(),
                        content: data.content.clone(),
                    });
                }
            }
        }

        // Cache miss - forward
        self.cache_misses += 1;
        ForwardDecision::Forward { interest_hash: hash }
    }

    /// Called when a data packet arrives from the producer, before the
    /// trapdoor update. The data is staged until the update completes.
    fn on_data(&mut self, interest_hash: &[u8], data: DataPacket) {
        self.staged_data.insert(interest_hash.to_vec(), data);
    }

    /// Called when a trapdoor update URI arrives from the producer.
    /// Uses the embedded hash to look up the pending interest and staged
    /// data, then updates the CS and trapdoor table.
    fn on_trapdoor_update(&mut self, uri: &str) {
        let (nt, hash) = decode_trapdoor_update(uri)
            .expect("router received malformed Tw update URI");

        // Look up the pending interest (removes it)
        let _interest_uri = self.pending.lookup_and_remove(&hash);

        // Look up staged data (removes it)
        if let Some(data) = self.staged_data.remove(&hash) {
            // Update CS: pair the trapdoor sequence with the data packet
            self.cs.insert(&nt.components, data);
            // Also add the trapdoor to the router's trapdoor table so future
            // interests can find it as an exact match.
            self.trapdoor_table.insert(nt, None);
        }
    }
}

enum ForwardDecision {
    ServeFromCache(DataPacket),
    Forward { interest_hash: Vec<u8> },
    Drop,
}


// -----------------------------------------------------------------------------
// Consumer
// -----------------------------------------------------------------------------

struct Consumer {
    public_key: PublicKey,
}

impl Consumer {
    fn new(public_key: PublicKey) -> Self {
        Consumer { public_key }
    }

    /// Create an encrypted interest URI for a name.
    fn create_interest(&self, name: &str) -> String {
        let nc = name_to_ciphertext(&self.public_key, name).unwrap();
        encode_ciphertext_name(&nc)
    }
}


// -----------------------------------------------------------------------------
// Main demo
// -----------------------------------------------------------------------------

fn main() {
    println!("=== PEKS-NDN End-to-End Demonstration ===\n");

    // Load names from file
    let names_content = fs::read_to_string(NAMES_FILE)
        .expect("failed to read names file");
    let names: Vec<&str> = names_content.lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    println!("Loaded {} names from {}", names.len(), NAMES_FILE);

    // Setup phase
    println!("\n--- Setup Phase ---");
    let mut producer = Producer::new("producer");
    println!("Producer generated keypair");

    // Producer registers content for each name
    let start = Instant::now();
    for name in &names {
        let data = format!("Data for {}", name).into_bytes();
        producer.register_content(name, data);
    }
    let setup_elapsed = start.elapsed();
    println!("Producer registered {} content items in {:.2?}",
             names.len(), setup_elapsed);

    let mut router = Router::new();

    // Producer sends prefix registration to router
    let reg_uri = producer.prefix_registration_uri();
    router.on_trapdoor_registration(&reg_uri);
    println!("Router received prefix registration");

    let consumer = Consumer::new(producer.public_key.clone());
    println!("Consumer initialized with producer's public key");

    // Request phase
    println!("\n--- Request Phase ({} requests) ---", NUM_REQUESTS);

    let mut rng = thread_rng();
    let mut total_elapsed = std::time::Duration::ZERO;
    let mut request_details: Vec<(String, bool, std::time::Duration)> = Vec::new();

    for i in 0..NUM_REQUESTS {
        let name = names.choose(&mut rng).unwrap();
        let start = Instant::now();

        // Consumer creates interest
        let interest_uri = consumer.create_interest(name);

        // Router receives interest
        let decision = router.on_interest(&interest_uri);

        let was_cache_hit;
        let received_content: Vec<u8>;

        match decision {
            ForwardDecision::ServeFromCache(data) => {
                was_cache_hit = true;
                received_content = data.content;
            }
            ForwardDecision::Forward { interest_hash } => {
                was_cache_hit = false;
                // Router forwards to producer
                match producer.on_interest(&interest_uri, &interest_hash) {
                    Some((data, update_uri)) => {
                        received_content = data.content.clone();
                        // Data packet flows back to router first
                        router.on_data(&interest_hash, data);
                        // Then trapdoor update follows
                        router.on_trapdoor_update(&update_uri);
                    }
                    None => {
                        println!("  [{}] Request for {} failed at producer!", i, name);
                        continue;
                    }
                }
            }
            ForwardDecision::Drop => {
                println!("  [{}] Request for {} dropped by router!", i, name);
                continue;
            }
        }

        let elapsed = start.elapsed();
        total_elapsed += elapsed;
        request_details.push((name.to_string(), was_cache_hit, elapsed));

        // Verify content is what we expected
        let expected = format!("Data for {}", name).into_bytes();
        if received_content != expected {
            println!("  [{}] Content mismatch for {}!", i, name);
        }
    }

    // Report metrics
    println!("\n--- Results ---");
    let total_requests = router.cache_hits + router.cache_misses;
    let hit_ratio = if total_requests > 0 {
        (router.cache_hits as f64 / total_requests as f64) * 100.0
    } else {
        0.0
    };

    println!("Total requests: {}", total_requests);
    println!("Cache hits: {}", router.cache_hits);
    println!("Cache misses: {}", router.cache_misses);
    println!("Cache hit ratio: {:.1}%", hit_ratio);
    println!("Total request phase time: {:.2?}", total_elapsed);
    println!("Average request time: {:.2?}",
             total_elapsed / total_requests as u32);

    // Compare hot path (cache hit) vs cold path (cache miss) times
    let hits: Vec<_> = request_details.iter().filter(|(_, h, _)| *h).collect();
    let misses: Vec<_> = request_details.iter().filter(|(_, h, _)| !h).collect();

    if !hits.is_empty() {
        let avg_hit: std::time::Duration = hits.iter().map(|(_, _, t)| *t).sum::<std::time::Duration>() / hits.len() as u32;
        println!("Average cache hit time: {:.2?}", avg_hit);
    }
    if !misses.is_empty() {
        let avg_miss: std::time::Duration = misses.iter().map(|(_, _, t)| *t).sum::<std::time::Duration>() / misses.len() as u32;
        println!("Average cache miss time: {:.2?}", avg_miss);
    }

    println!("\nCS size at end: {} entries", router.cs.len());
    println!("Trapdoor table size at end: {} entries", router.trapdoor_table.len());
}