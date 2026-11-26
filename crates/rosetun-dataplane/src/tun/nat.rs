use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// A socket mapping is independent of the remote destination. Egress identity
/// remains in the key so a direct mapping cannot be used by proxy-only traffic.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MappingKey<E> {
    pub source: SocketAddr,
    pub egress: E,
}

impl<E> fmt::Debug for MappingKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MappingKey").finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MappingError<E> {
    #[error("UDP mapping table is full")]
    Capacity,
    #[error("cannot create UDP mapping: {0}")]
    Open(E),
}

struct Mapping<V> {
    active_at: Instant,
    path: V,
}

/// Bounded endpoint-independent UDP mapping table.
pub struct FullConeNat<E, V> {
    entries: HashMap<MappingKey<E>, Mapping<V>>,
    capacity: usize,
    idle: Duration,
    sweep_at: Option<Instant>,
}

impl<E, V> fmt::Debug for FullConeNat<E, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FullConeNat")
            .field("mappings", &self.entries.len())
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl<E: Eq + Hash, V> FullConeNat<E, V> {
    pub fn new(capacity: usize, idle: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            idle,
            sweep_at: None,
        }
    }

    /// Reuses the same bound socket for every destination on the selected egress.
    pub fn path<T>(
        &mut self,
        key: MappingKey<E>,
        now: Instant,
        open: impl FnOnce() -> Result<V, T>,
    ) -> Result<&mut V, MappingError<T>> {
        self.expire(now);
        let at_capacity = self.entries.len() >= self.capacity;
        match self.entries.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                let mapping = entry.into_mut();
                mapping.active_at = now;
                Ok(&mut mapping.path)
            }
            std::collections::hash_map::Entry::Vacant(entry) if !at_capacity => {
                let path = open().map_err(MappingError::Open)?;
                Ok(&mut entry
                    .insert(Mapping {
                        active_at: now,
                        path,
                    })
                    .path)
            }
            std::collections::hash_map::Entry::Vacant(_) => Err(MappingError::Capacity),
        }
    }

    /// Polls established sockets. Any accepted inbound datagram extends the mapping.
    pub fn receive(&mut self, now: Instant, mut poll: impl FnMut(&MappingKey<E>, &mut V) -> bool) {
        self.expire(now);
        for (key, mapping) in &mut self.entries {
            if poll(key, &mut mapping.path) {
                mapping.active_at = now;
            }
        }
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&MappingKey<E>, &V) -> bool) {
        self.entries.retain(|key, mapping| keep(key, &mapping.path));
    }

    pub fn touch(&mut self, key: &MappingKey<E>, now: Instant) -> bool {
        if let Some(mapping) = self.entries.get_mut(key) {
            mapping.active_at = now;
            true
        } else {
            false
        }
    }

    pub fn drain(&mut self) -> impl Iterator<Item = V> + '_ {
        self.entries.drain().map(|(_, mapping)| mapping.path)
    }

    fn expire(&mut self, now: Instant) {
        if self.sweep_at.is_some_and(|next| now < next) && self.entries.len() < self.capacity {
            return;
        }
        self.sweep_at = now.checked_add(Duration::from_secs(1));
        let idle = self.idle;
        self.entries
            .retain(|_, mapping| now.saturating_duration_since(mapping.active_at) < idle);
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn destinations_share_one_mapping_but_another_egress_does_not() {
        let now = Instant::now();
        let mut nat = FullConeNat::new(2, Duration::from_secs(10));
        let source = "192.0.2.1:12345".parse().unwrap();
        let direct = MappingKey { source, egress: 1 };
        let proxy = MappingKey { source, egress: 2 };
        let mut sends = |egress, target: &str| {
            nat.path(egress, now, || Ok::<_, io::Error>(Vec::new()))
                .unwrap()
                .push(target.parse::<SocketAddr>().unwrap());
        };
        sends(direct, "198.51.100.1:443");
        sends(direct, "203.0.113.1:5001");
        sends(proxy, "198.51.100.1:443");
        nat.receive(now, |key, path| {
            assert_eq!(path.len(), if *key == direct { 2 } else { 1 });
            true
        });
    }

    #[test]
    fn capacity_does_not_evict_a_live_mapping_and_inbound_traffic_extends_it() {
        let now = Instant::now();
        let mut nat = FullConeNat::new(1, Duration::from_secs(5));
        let a = MappingKey {
            source: "[2001:db8::a]:3500".parse().unwrap(),
            egress: (),
        };
        let b = MappingKey {
            source: "[2001:db8::b]:3500".parse().unwrap(),
            egress: (),
        };
        assert_eq!(*nat.path(a, now, || Ok::<_, io::Error>(1)).unwrap(), 1);
        nat.receive(now + Duration::from_secs(4), |_, _| true);
        assert!(matches!(
            nat.path(b, now + Duration::from_secs(7), || Ok::<_, io::Error>(2)),
            Err(MappingError::Capacity)
        ));
        assert_eq!(
            *nat.path(b, now + Duration::from_secs(10), || Ok::<_, io::Error>(3))
                .unwrap(),
            3
        );
    }
}
