use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use super::InventoryAttestationSuccess;

#[derive(Clone)]
struct CachedInventoryAttestation {
    response: InventoryAttestationSuccess,
    inserted_at: Instant,
}

/// Thread-safe LRU cache for inventory attestations, keyed by `{steamId}:{assetId}`.
pub struct InventoryAttestationCache {
    inner: Mutex<LruCache<String, CachedInventoryAttestation>>,
    ttl: Duration,
}

impl InventoryAttestationCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("cache capacity must be > 0"),
            )),
            ttl,
        }
    }

    pub fn get(&self, cache_key: &str) -> Option<InventoryAttestationSuccess> {
        let mut cache = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let entry = cache.get(cache_key)?;
        if entry.inserted_at.elapsed() > self.ttl {
            cache.pop(cache_key);
            return None;
        }

        Some(entry.response.clone())
    }

    pub fn insert(&self, cache_key: String, response: InventoryAttestationSuccess) {
        let entry = CachedInventoryAttestation {
            response,
            inserted_at: Instant::now(),
        };
        let mut cache = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        cache.put(cache_key, entry);
    }
}
