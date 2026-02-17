/// Round `n` up to the next multiple of `align`.
#[inline]
pub fn align_up(n: u64, align: u64) -> u64 {
    debug_assert!(align > 0 && align.is_power_of_two());
    (n + align - 1) & !(align - 1)
}

/// How many padding bytes are needed to align `n` to `align`.
#[inline]
pub fn padding_needed(n: u64, align: u64) -> u64 {
    align_up(n, align) - n
}

/// Round `n` down to the previous multiple of `align`.
#[inline]
pub fn align_down(n: u64, align: u64) -> u64 {
    debug_assert!(align > 0 && align.is_power_of_two());
    n & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 16), 0);
        assert_eq!(align_up(1, 16), 16);
        assert_eq!(align_up(16, 16), 16);
        assert_eq!(align_up(17, 16), 32);
        assert_eq!(align_up(0x200, 0x200), 0x200);
        assert_eq!(align_up(0x201, 0x200), 0x400);
    }

    #[test]
    fn test_padding_needed() {
        assert_eq!(padding_needed(0, 16), 0);
        assert_eq!(padding_needed(1, 16), 15);
        assert_eq!(padding_needed(16, 16), 0);
        assert_eq!(padding_needed(17, 16), 15);
    }

    #[test]
    fn test_align_down() {
        assert_eq!(align_down(0, 16), 0);
        assert_eq!(align_down(15, 16), 0);
        assert_eq!(align_down(16, 16), 16);
        assert_eq!(align_down(17, 16), 16);
    }
}
