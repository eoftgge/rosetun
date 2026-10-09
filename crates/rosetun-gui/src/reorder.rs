/// `slot` is a gap in the full list. Removing an item shifts later gaps left.
pub(crate) fn drop_target(from: usize, slot: usize, len: usize) -> Option<usize> {
    group_drop_target(&[from], slot, len)
}

/// Convert a full-list gap into a gap after removing selected positions.
/// A contiguous block dropped on itself stays in place; scattered rules may consolidate at any gap.
pub(crate) fn group_drop_target(selected: &[usize], slot: usize, len: usize) -> Option<usize> {
    let (&first, &last) = (selected.first()?, selected.last()?);
    if slot > len || last >= len || selected.windows(2).any(|pair| pair[0] >= pair[1]) {
        return None;
    }
    let target = slot - selected.partition_point(|index| *index < slot);
    let contiguous = selected.windows(2).all(|pair| pair[1] == pair[0] + 1);
    (target != first || !contiguous).then_some(target)
}

#[cfg(test)]
mod tests {
    use super::{drop_target, group_drop_target};

    #[test]
    fn drop_slots_account_for_removal_before_insertion() {
        assert_eq!(drop_target(3, 1, 5), Some(1));
        assert_eq!(drop_target(1, 4, 5), Some(3));
        assert_eq!(drop_target(0, 5, 5), Some(4));
        assert_eq!(drop_target(2, 2, 5), None);
        assert_eq!(drop_target(2, 3, 5), None);
        assert_eq!(drop_target(5, 0, 5), None);
        assert_eq!(drop_target(0, 6, 5), None);
    }

    #[test]
    fn group_drop_uses_positions_after_removal() {
        for (slot, target) in [(0, 0), (1, 1), (2, 1), (3, 2), (4, 2), (5, 3)] {
            assert_eq!(group_drop_target(&[1, 3], slot, 5), Some(target));
        }
        assert_eq!(group_drop_target(&[0, 2], 0, 4), Some(0));
        assert_eq!(group_drop_target(&[1, 4], 5, 5), Some(3));
        assert_eq!(group_drop_target(&[0, 2], 5, 5), Some(3));
        assert_eq!(group_drop_target(&[2, 4], 0, 5), Some(0));
    }

    #[test]
    fn contiguous_group_dropped_inside_itself_does_not_move() {
        for slot in 1..=3 {
            assert_eq!(group_drop_target(&[1, 2], slot, 5), None);
        }
        assert_eq!(group_drop_target(&[1, 2], 0, 5), Some(0));
        assert_eq!(group_drop_target(&[1, 2], 4, 5), Some(2));
    }

    #[test]
    fn group_drop_rejects_invalid_positions_and_slots() {
        assert_eq!(group_drop_target(&[], 0, 3), None);
        assert_eq!(group_drop_target(&[0, 0], 3, 3), None);
        assert_eq!(group_drop_target(&[2, 1], 3, 3), None);
        assert_eq!(group_drop_target(&[3], 0, 3), None);
        assert_eq!(group_drop_target(&[0], 4, 3), None);
    }
}
