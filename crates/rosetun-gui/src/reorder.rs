/// `slot` is a gap in the full list. Removing an item shifts later gaps left.
pub(crate) fn drop_target(from: usize, slot: usize, len: usize) -> Option<usize> {
    if from >= len || slot > len {
        return None;
    }
    let target = slot - usize::from(slot > from);
    (target != from).then_some(target)
}

#[cfg(test)]
mod tests {
    use super::drop_target;

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
}
