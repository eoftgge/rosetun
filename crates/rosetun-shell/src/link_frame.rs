//! The message a later GUI instance hands a `rosetun://` link in: a
//! little-endian `u32` length, then that many bytes of UTF-8.

use std::io::{self, Read};

/// The longest link accepted from another instance, the same bound as the link parser.
pub const MAX_LINK_BYTES: usize = 8 * 1024;

/// `link` as one message; `InvalidInput` when it is too long to be read back.
pub(crate) fn encode_link(link: &str) -> io::Result<Vec<u8>> {
    if link.len() > MAX_LINK_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the link is too long",
        ));
    }
    let mut message = Vec::with_capacity(4 + link.len());
    message.extend_from_slice(&(link.len() as u32).to_le_bytes());
    message.extend_from_slice(link.as_bytes());
    Ok(message)
}

/// The next message's link; `None` when it is cut short, too long or not UTF-8.
pub(crate) fn read_link(reader: &mut impl Read) -> Option<String> {
    let mut length = [0; 4];
    reader.read_exact(&mut length).ok()?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_LINK_BYTES {
        return None;
    }
    let mut link = vec![0; length];
    reader.read_exact(&mut link).ok()?;
    String::from_utf8(link).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_reads_back_as_written() {
        let link = "rosetun://add/https://example.com/подписка";
        let message = encode_link(link).unwrap();
        assert_eq!(read_link(&mut message.as_slice()).as_deref(), Some(link));
        let longest = "a".repeat(MAX_LINK_BYTES);
        let message = encode_link(&longest).unwrap();
        assert_eq!(read_link(&mut message.as_slice()), Some(longest));
    }

    #[test]
    fn a_link_over_the_bound_is_refused_on_both_sides() {
        assert_eq!(
            encode_link(&"a".repeat(MAX_LINK_BYTES + 1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let length = (MAX_LINK_BYTES as u32 + 1).to_le_bytes();
        assert_eq!(read_link(&mut length.as_slice()), None);
    }

    #[test]
    fn a_cut_or_invalid_message_is_no_link() {
        assert_eq!(read_link(&mut [1u8, 0].as_slice()), None);
        assert_eq!(read_link(&mut [4u8, 0, 0, 0, b'a'].as_slice()), None);
        assert_eq!(read_link(&mut [1u8, 0, 0, 0, 0xff].as_slice()), None);
    }
}
