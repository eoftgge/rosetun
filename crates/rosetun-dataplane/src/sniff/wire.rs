//! Bounds-checked big-endian reader shared by the TLS and QUIC parsers.

#[derive(Clone, Copy)]
pub(super) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(super) fn remaining(&self) -> usize {
        self.data.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(super) fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.data.split_at_checked(len)?;
        self.data = tail;
        Some(head)
    }

    pub(super) fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    pub(super) fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    pub(super) fn u24(&mut self) -> Option<usize> {
        let bytes = self.take(3)?;
        Some(
            bytes
                .iter()
                .fold(0, |acc, byte| (acc << 8) | usize::from(*byte)),
        )
    }

    pub(super) fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    /// QUIC variable-length integer (RFC 9000 §16).
    pub(super) fn varint(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let extra = match first >> 6 {
            0 => 0,
            1 => 1,
            2 => 3,
            _ => 7,
        };
        let tail = self.take(extra)?;
        Some(tail.iter().fold(u64::from(first & 0x3f), |acc, byte| {
            (acc << 8) | u64::from(*byte)
        }))
    }

    pub(super) fn varint_len(&mut self) -> Option<usize> {
        usize::try_from(self.varint()?).ok()
    }

    /// A vector with a one-byte length prefix.
    pub(super) fn vec8(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    /// A vector with a two-byte length prefix.
    pub(super) fn vec16(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
}
