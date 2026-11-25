//! Domain suffix matching: reversed-label trie and sing-box succinct domain
//! trie (`sagernet/sing/common/domain`).

use std::collections::{HashMap, HashSet};
use std::fmt;

use super::RulesError;

/// Matches a domain suffix and the domain itself (sing-box SRS v2+ `rootLabel`).
pub(crate) const ROOT_LABEL: u8 = b'\n';
/// Matches any subdomain prefix after a dot (sing-box SRS `prefixLabel`).
pub(crate) const PREFIX_LABEL: u8 = b'\r';
/// Wildcard edge in AdGuard domain matchers.
const WILDCARD_LABEL: u8 = b'*';
/// Upper bound on wildcard search states per domain query.
const MAX_WILDCARD_STEPS: usize = 4096;

/// Matches `domain` against `suffix` with sing-box `domain_suffix` semantics:
/// the domain itself and its subdomains, or only subdomains when `suffix`
/// starts with a dot. Both inputs must already be lowercased.
pub(crate) fn has_suffix(domain: &str, suffix: &str) -> bool {
    if suffix.starts_with('.') {
        domain.ends_with(suffix)
    } else {
        domain == suffix
            || domain
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.ends_with('.'))
    }
}

#[derive(Default)]
struct SuffixNode {
    children: HashMap<String, usize>,
    /// Matches when a domain ends at this label or has more labels to the left.
    match_self_and_sub: bool,
    /// Matches only when at least one more label precedes this suffix (leading dot).
    match_sub_only: bool,
}

/// Reversed-label trie implementing [`has_suffix`] over a set of suffixes.
#[derive(Default)]
pub(crate) struct SuffixTrie {
    nodes: Vec<SuffixNode>,
    match_trailing_dot: bool,
    match_empty_or_trailing_dot: bool,
    entry_count: usize,
}

impl fmt::Debug for SuffixTrie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SuffixTrie")
            .field("entries", &self.entry_count)
            .finish()
    }
}

impl SuffixTrie {
    pub(crate) fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    pub(crate) fn insert(&mut self, suffix: &str) {
        let lower = suffix.to_lowercase();
        let (sub_only, core) = match lower.strip_prefix('.') {
            Some(rest) => (true, rest),
            None => (false, lower.as_str()),
        };
        self.entry_count += 1;
        if core.is_empty() {
            if sub_only {
                self.match_trailing_dot = true;
            } else {
                self.match_empty_or_trailing_dot = true;
            }
            return;
        }
        if self.nodes.is_empty() {
            self.nodes.push(SuffixNode::default());
        }
        let mut cur = 0_usize;
        for label in core.rsplit('.') {
            if let Some(&next) = self.nodes[cur].children.get(label) {
                cur = next;
            } else {
                let next = self.nodes.len();
                self.nodes.push(SuffixNode::default());
                self.nodes[cur].children.insert(label.to_owned(), next);
                cur = next;
            }
        }
        if sub_only {
            self.nodes[cur].match_sub_only = true;
        } else {
            self.nodes[cur].match_self_and_sub = true;
        }
    }

    pub(crate) fn matches(&self, domain: &str) -> bool {
        if self.entry_count == 0 {
            return false;
        }
        if self.match_trailing_dot && domain.ends_with('.') {
            return true;
        }
        if self.match_empty_or_trailing_dot && (domain.is_empty() || domain.ends_with('.')) {
            return true;
        }
        if self.nodes.is_empty() {
            return false;
        }
        let mut parts = domain.rsplit('.').peekable();
        let mut cur = 0_usize;
        while let Some(label) = parts.next() {
            let Some(&next) = self.nodes[cur].children.get(label) else {
                return false;
            };
            cur = next;
            let node = &self.nodes[cur];
            if node.match_self_and_sub {
                return true;
            }
            if node.match_sub_only && parts.peek().is_some() {
                return true;
            }
        }
        false
    }
}

/// Decoded LOUDS succinct domain trie from sing-box `.srs` files
/// (`domain.Matcher` and `domain.AdGuardMatcher`).
pub(crate) struct SuccinctDomainSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    /// Cumulative count of `1`-bits before each word of `label_bitmap`, plus
    /// the total `1`-bit count at the final slot.
    ones_prefix: Vec<usize>,
    labels: Vec<u8>,
    allow_wildcard: bool,
}

impl fmt::Debug for SuccinctDomainSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SuccinctDomainSet")
            .field("labels_len", &self.labels.len())
            .field("wildcard", &self.allow_wildcard)
            .finish()
    }
}

impl SuccinctDomainSet {
    /// Validates and wraps the decoded succinct trie arrays.
    pub(crate) fn from_raw(
        leaves: Vec<u64>,
        label_bitmap: Vec<u64>,
        labels: Vec<u8>,
        allow_wildcard: bool,
    ) -> Result<Self, RulesError> {
        if labels.is_empty() || label_bitmap.is_empty() {
            return Err(RulesError::InvalidSrs);
        }
        let mut ones_prefix = Vec::with_capacity(label_bitmap.len() + 1);
        let mut total_ones = 0_usize;
        let mut last_one_pos = None;
        for (word_idx, &word) in label_bitmap.iter().enumerate() {
            ones_prefix.push(total_ones);
            if word != 0 {
                let high_bit = 63 - word.leading_zeros() as usize;
                last_one_pos = Some(word_idx * 64 + high_bit);
                total_ones += word.count_ones() as usize;
            }
        }
        ones_prefix.push(total_ones);

        let Some(last_one_pos) = last_one_pos else {
            return Err(RulesError::InvalidSrs);
        };
        // Every node ends with a `1`-bit and every edge is a `0`-bit before the
        // last node's terminator, so `zeros == labels.len()` and `ones == labels.len() + 1`.
        let zeros_before_last = last_one_pos
            .checked_add(1)
            .and_then(|bits| bits.checked_sub(total_ones))
            .ok_or(RulesError::InvalidSrs)?;
        if total_ones == 0 || zeros_before_last != labels.len() {
            return Err(RulesError::InvalidSrs);
        }
        let set = Self {
            leaves,
            label_bitmap,
            ones_prefix,
            labels,
            allow_wildcard,
        };
        // Verify each node's outgoing labels are strictly sorted so binary
        // search and leading-sentinel scans cannot misbehave on crafted inputs.
        for node_id in 0..total_ones {
            let (start, end) = set.node_label_range(node_id)?;
            let slice = &set.labels[start..end];
            if slice.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(RulesError::InvalidSrs);
            }
        }
        Ok(set)
    }

    /// Matches a lowercased domain against the succinct trie.
    pub(crate) fn matches(&self, domain: &str) -> bool {
        let bytes = domain.as_bytes();
        if self.allow_wildcard {
            self.matches_wildcard(bytes)
        } else {
            self.matches_exact_or_suffix(bytes)
        }
    }

    fn matches_exact_or_suffix(&self, bytes: &[u8]) -> bool {
        let len = bytes.len();
        let mut node_id = 0_usize;
        for i in 0..=len {
            let Ok((start, end)) = self.node_label_range(node_id) else {
                return false;
            };
            let slice = &self.labels[start..end];
            for &edge in slice {
                if edge > PREFIX_LABEL {
                    break;
                }
                if edge == PREFIX_LABEL {
                    return true;
                }
                if edge == ROOT_LABEL && (i == len || bytes[len - 1 - i] == b'.') {
                    return true;
                }
            }
            if i == len {
                return self.is_leaf(node_id);
            }
            let target = bytes[len - 1 - i];
            let Ok(offset) = slice.binary_search(&target) else {
                return false;
            };
            node_id = start + offset + 1;
        }
        false
    }

    fn matches_wildcard(&self, bytes: &[u8]) -> bool {
        let len = bytes.len();
        let mut stack = vec![(0_usize, 0_usize)];
        let mut visited = HashSet::new();
        let mut steps = 0_usize;

        while let Some((node_id, i)) = stack.pop() {
            if !visited.insert((node_id, i)) {
                continue;
            }
            steps += 1;
            if steps > MAX_WILDCARD_STEPS {
                return false;
            }
            let Ok((start, end)) = self.node_label_range(node_id) else {
                continue;
            };
            let slice = &self.labels[start..end];
            for &edge in slice {
                if edge > PREFIX_LABEL {
                    break;
                }
                if edge == PREFIX_LABEL {
                    return true;
                }
                if edge == ROOT_LABEL && (i == len || bytes[len - 1 - i] == b'.') {
                    return true;
                }
            }
            if i == len && self.is_leaf(node_id) {
                return true;
            }
            if let Ok(star_offset) = slice.binary_search(&WILDCARD_LABEL) {
                let star_child = start + star_offset + 1;
                for next_i in i..=len {
                    stack.push((star_child, next_i));
                }
            }
            if i < len
                && let Ok(offset) = slice.binary_search(&bytes[len - 1 - i])
            {
                stack.push((start + offset + 1, i + 1));
            }
        }
        false
    }

    fn is_leaf(&self, node_id: usize) -> bool {
        self.leaves
            .get(node_id / 64)
            .is_some_and(|word| (word >> (node_id % 64)) & 1 != 0)
    }

    fn node_label_range(&self, node_id: usize) -> Result<(usize, usize), RulesError> {
        let bm_start = if node_id == 0 {
            0
        } else {
            self.select1(node_id - 1)? + 1
        };
        let bm_end = self.select1(node_id)?;
        let start = bm_start
            .checked_sub(node_id)
            .ok_or(RulesError::InvalidSrs)?;
        let end = bm_end.checked_sub(node_id).ok_or(RulesError::InvalidSrs)?;
        if start > end || end > self.labels.len() {
            return Err(RulesError::InvalidSrs);
        }
        Ok((start, end))
    }

    /// Returns the bit index of the `rank`-th `1`-bit (0-indexed) in `label_bitmap`.
    fn select1(&self, rank: usize) -> Result<usize, RulesError> {
        let total = *self.ones_prefix.last().unwrap_or(&0);
        if rank >= total {
            return Err(RulesError::InvalidSrs);
        }
        // Largest word index `w` with `ones_prefix[w] <= rank`.
        let word_idx = self.ones_prefix.partition_point(|&count| count <= rank) - 1;
        let mut remaining = rank - self.ones_prefix[word_idx];
        let mut word = self.label_bitmap[word_idx];
        while remaining > 0 {
            word &= word - 1;
            remaining -= 1;
        }
        Ok(word_idx * 64 + word.trailing_zeros() as usize)
    }
}

/// Test-only succinct domain trie encoder matching `sagernet/sing/common/domain`.
#[cfg(test)]
pub(crate) fn encode_succinct_domains(
    exact: &[&str],
    suffixes: &[&str],
    legacy_v1: bool,
) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
    let mut keys = Vec::new();
    for domain in suffixes {
        let lower = domain.to_lowercase();
        if lower.starts_with('.') {
            let mut key = reverse_bytes(lower.as_bytes());
            key.push(PREFIX_LABEL);
            keys.push(key);
        } else if legacy_v1 {
            let rev = reverse_bytes(lower.as_bytes());
            keys.push(rev.clone());
            let mut sub = rev;
            sub.push(b'.');
            sub.push(PREFIX_LABEL);
            keys.push(sub);
        } else {
            let mut key = reverse_bytes(lower.as_bytes());
            key.push(ROOT_LABEL);
            keys.push(key);
        }
    }
    for domain in exact {
        let lower = domain.to_lowercase();
        keys.push(reverse_bytes(lower.as_bytes()));
    }
    encode_succinct_raw_keys(keys)
}

#[cfg(test)]
pub(crate) fn encode_succinct_raw_keys(mut keys: Vec<Vec<u8>>) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
    use std::collections::{BTreeMap, VecDeque};

    #[derive(Default)]
    struct BuildNode {
        children: BTreeMap<u8, usize>,
        leaf: bool,
    }

    keys.sort();
    keys.dedup();

    let mut arena = vec![BuildNode::default()];
    for key in keys {
        let mut cur = 0_usize;
        for byte in key {
            if let Some(&next) = arena[cur].children.get(&byte) {
                cur = next;
            } else {
                let next = arena.len();
                arena.push(BuildNode::default());
                arena[cur].children.insert(byte, next);
                cur = next;
            }
        }
        arena[cur].leaf = true;
    }

    let mut leaves = Vec::<u64>::new();
    let mut label_bitmap = Vec::<u64>::new();
    let mut labels = Vec::<u8>::new();
    let mut bm_bit = 0_usize;
    let mut node_id = 0_usize;

    let mut queue = VecDeque::new();
    queue.push_back(0_usize);
    while let Some(idx) = queue.pop_front() {
        if arena[idx].leaf {
            set_bit(&mut leaves, node_id);
        }
        for (&edge, &child) in &arena[idx].children {
            labels.push(edge);
            // `0`-bit for each outgoing edge; allocate the bitmap word if needed.
            ensure_bit_len(&mut label_bitmap, bm_bit + 1);
            bm_bit += 1;
            queue.push_back(child);
        }
        set_bit(&mut label_bitmap, bm_bit);
        bm_bit += 1;
        node_id += 1;
    }

    if leaves.is_empty() {
        leaves.push(0);
    }
    (leaves, label_bitmap, labels)
}

#[cfg(test)]
fn reverse_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().rev().collect()
}

#[cfg(test)]
fn ensure_bit_len(words: &mut Vec<u64>, bits: usize) {
    let needed = bits.div_ceil(64);
    if words.len() < needed {
        words.resize(needed, 0);
    }
}

#[cfg(test)]
fn set_bit(words: &mut Vec<u64>, bit: usize) {
    ensure_bit_len(words, bit + 1);
    words[bit / 64] |= 1_u64 << (bit % 64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_trie_agrees_with_has_suffix_on_all_boundary_cases() {
        let suffixes = [
            "example.com",
            ".sub.example.org",
            "..double.example.net",
            "trailing.invalid.",
        ];
        let mut trie = SuffixTrie::default();
        for suffix in suffixes {
            trie.insert(suffix);
        }

        let probes = [
            "example.com",
            "www.example.com",
            "a.b.example.com",
            "badexample.com",
            "example.com.invalid",
            "sub.example.org",
            "a.sub.example.org",
            ".sub.example.org",
            "not-sub.example.org",
            "double.example.net",
            ".double.example.net",
            "..double.example.net",
            "a..double.example.net",
            "trailing.invalid",
            "trailing.invalid.",
            "a.trailing.invalid.",
            "",
        ];
        for domain in probes {
            let expected = suffixes.iter().any(|suffix| has_suffix(domain, suffix));
            assert_eq!(trie.matches(domain), expected, "{domain}");
        }
    }

    #[test]
    fn succinct_domain_set_round_trips_v1_and_v2_semantics() {
        for legacy_v1 in [true, false] {
            let (leaves, bm, labels) = encode_succinct_domains(
                &["a.example.com"],
                &["example.org", ".sub.example.net"],
                legacy_v1,
            );
            let set = SuccinctDomainSet::from_raw(leaves, bm, labels, false).unwrap();

            assert!(set.matches("a.example.com"));
            assert!(!set.matches("b.a.example.com"));
            assert!(!set.matches("example.com"));

            assert!(set.matches("example.org"));
            assert!(set.matches("www.example.org"));
            assert!(set.matches("deep.www.example.org"));
            assert!(!set.matches("badexample.org"));

            assert!(!set.matches("sub.example.net"));
            assert!(set.matches("x.sub.example.net"));
            assert!(set.matches("y.x.sub.example.net"));
            assert!(!set.matches("notsub.example.net"));
        }
    }

    #[test]
    fn succinct_domain_set_supports_adguard_wildcards() {
        let mut k1 = reverse_bytes(b"foo*bar.example.net");
        k1.push(ROOT_LABEL);
        let (leaves, bm, labels) = encode_succinct_raw_keys(vec![k1]);
        let set = SuccinctDomainSet::from_raw(leaves, bm, labels, true).unwrap();

        assert!(set.matches("foobar.example.net"));
        assert!(set.matches("foo123bar.example.net"));
        assert!(set.matches("sub.foo123bar.example.net"));
        assert!(!set.matches("foobaz.example.net"));
        assert!(!set.matches("example.net"));

        let mut k2 = reverse_bytes(b"example.*");
        k2.push(ROOT_LABEL);
        let (leaves, bm, labels) = encode_succinct_raw_keys(vec![k2]);
        let tld_wildcard = SuccinctDomainSet::from_raw(leaves, bm, labels, true).unwrap();
        assert!(tld_wildcard.matches("example.com"));
        assert!(tld_wildcard.matches("www.example.invalid"));
        assert!(!tld_wildcard.matches("notexample.invalid"));
    }

    #[test]
    fn succinct_domain_encoder_matches_sing_box_wire_bytes() {
        // Verified against sing-box 1.14.3 rule-set compile for version 1 and 2.
        let (leaves_v1, bm_v1, labels_v1) = encode_succinct_domains(
            &["a.example.com"],
            &["example.org", ".sub.example.net"],
            true,
        );
        assert_eq!(leaves_v1, vec![0x0000_0860_8000_0000]);
        assert_eq!(bm_v1, vec![0xaaaa_aaaa_aaaa_aaa8, 0x0000_0000_006a_baaa]);
        assert_eq!(labels_v1, b"gmtroeocn...eeelllpppmmmaaaxxxeee...\rabus.\r");

        let (leaves_v2, bm_v2, labels_v2) = encode_succinct_domains(
            &["a.example.com"],
            &["example.org", ".sub.example.net"],
            false,
        );
        assert_eq!(leaves_v2, vec![0x0000_0424_0000_0000]);
        assert_eq!(bm_v2, vec![0xaaaa_aaaa_aaaa_aaa8, 0x0000_0000_001a_ad6a]);
        assert_eq!(labels_v2, b"gmtroeocn...eeelllpppmmmaaaxxxeee\n..abus.\r");
    }

    #[test]
    fn succinct_domain_set_rejects_empty_and_unsorted_bitmaps() {
        assert!(SuccinctDomainSet::from_raw(vec![0], vec![], vec![], false).is_err());
        assert!(SuccinctDomainSet::from_raw(vec![0], vec![0], vec![b'a'], false).is_err());
        // Unsorted sibling labels: 'b' before 'a' under root.
        assert!(
            SuccinctDomainSet::from_raw(vec![0b110], vec![0b11100], vec![b'b', b'a'], false)
                .is_err()
        );
    }
}
