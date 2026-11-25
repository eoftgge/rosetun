//! A bounded cache whose entries expire and whose least recently used entry
//! goes first. Time comes from the caller, so tests need no sleeping.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Instant;

/// Where the service reads the time from.
pub(crate) type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

pub(crate) fn system_clock() -> Clock {
    Arc::new(Instant::now)
}

struct Slot<V> {
    value: V,
    expires: Instant,
    tick: u64,
}

pub(crate) struct TtlCache<K, V> {
    capacity: usize,
    entries: HashMap<K, Slot<V>>,
    /// Keys by recency: the first one is the next to be evicted.
    order: BTreeMap<u64, K>,
    tick: u64,
}

impl<K, V> fmt::Debug for TtlCache<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TtlCache")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl<K: Hash + Eq + Clone, V> TtlCache<K, V> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            tick: 0,
        }
    }

    /// Entries held, expired ones included until they are looked up or evicted.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    pub(crate) fn get(&mut self, key: &K, now: Instant) -> Option<&V> {
        if self.entries.get(key)?.expires <= now {
            self.remove(key);
            return None;
        }
        let tick = self.next_tick();
        let slot = self.entries.get_mut(key)?;
        self.order.remove(&slot.tick);
        slot.tick = tick;
        self.order.insert(tick, key.clone());
        Some(&slot.value)
    }

    pub(crate) fn insert(&mut self, key: K, value: V, expires: Instant) {
        if self.capacity == 0 {
            return;
        }
        self.remove(&key);
        let tick = self.next_tick();
        self.order.insert(tick, key.clone());
        self.entries.insert(
            key,
            Slot {
                value,
                expires,
                tick,
            },
        );
        while self.entries.len() > self.capacity {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    fn remove(&mut self, key: &K) {
        if let Some(slot) = self.entries.remove(key) {
            self.order.remove(&slot.tick);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn an_entry_expires_when_its_time_has_come() {
        let start = Instant::now();
        let mut cache = TtlCache::new(4);
        cache.insert("a", 1, start + Duration::from_secs(30));
        assert_eq!(cache.get(&"a", start + Duration::from_secs(29)), Some(&1));
        assert_eq!(cache.get(&"a", start + Duration::from_secs(30)), None);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn the_least_recently_used_entry_is_evicted_first() {
        let start = Instant::now();
        let later = start + Duration::from_secs(60);
        let mut cache = TtlCache::new(2);
        cache.insert("a", 1, later);
        cache.insert("b", 2, later);
        assert_eq!(cache.get(&"a", start), Some(&1));
        cache.insert("c", 3, later);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&"b", start), None);
        assert_eq!(cache.get(&"a", start), Some(&1));
        assert_eq!(cache.get(&"c", start), Some(&3));
    }

    #[test]
    fn inserting_a_key_again_replaces_it_without_growing() {
        let start = Instant::now();
        let later = start + Duration::from_secs(60);
        let mut cache = TtlCache::new(2);
        cache.insert("a", 1, later);
        cache.insert("a", 2, later);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&"a", start), Some(&2));
    }

    #[test]
    fn a_cache_without_room_keeps_nothing() {
        let start = Instant::now();
        let mut cache = TtlCache::new(0);
        cache.insert("a", 1, start + Duration::from_secs(60));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn clearing_forgets_every_entry() {
        let start = Instant::now();
        let mut cache = TtlCache::new(3);
        cache.insert("a", 1, start + Duration::from_secs(60));
        cache.clear();
        assert_eq!(cache.get(&"a", start), None);
        assert_eq!(cache.len(), 0);
    }
}
