use std::fmt;

/// TCP sequence number with RFC 9293 §3.4 modular comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeqNum(pub u32);

impl SeqNum {
    pub fn wrapping_add(self, n: u32) -> SeqNum {
        SeqNum(self.0.wrapping_add(n))
    }
    /// `other - self` as a wrapping signed distance.
    pub fn distance(self, other: SeqNum) -> i32 {
        other.0.wrapping_sub(self.0) as i32
    }
    pub fn lt(self, o: SeqNum) -> bool {
        self.distance(o) > 0
    }
    pub fn le(self, o: SeqNum) -> bool {
        self.distance(o) >= 0
    }
    pub fn gt(self, o: SeqNum) -> bool {
        self.distance(o) < 0
    }
    pub fn ge(self, o: SeqNum) -> bool {
        self.distance(o) <= 0
    }
}

impl fmt::Display for SeqNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seq_wraps() {
        let a = SeqNum(0xFFFF_FFF0);
        assert_eq!(a.wrapping_add(0x20), SeqNum(0x10));
    }
    #[test]
    fn seq_order_across_wrap() {
        assert!(SeqNum(0xFFFF_FFF0).lt(SeqNum(0x10)));
        assert!(SeqNum(0x10).gt(SeqNum(0xFFFF_FFF0)));
    }
    #[test]
    fn seq_distance_signed() {
        assert_eq!(SeqNum(0xFFFF_FFF0).distance(SeqNum(0x10)), 0x20);
        assert_eq!(SeqNum(0x10).distance(SeqNum(0xFFFF_FFF0)), -0x20);
    }
}
