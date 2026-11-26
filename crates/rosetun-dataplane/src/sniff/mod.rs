//! Bounded, timeout-protected protocol sniffer.
//!
//! Extracts the destination domain from the first bytes of a flow: the TLS
//! SNI of a ClientHello, the `Host` of an HTTP/1.x request, or the SNI inside
//! a QUIC Initial packet. Nothing here panics on hostile input, allocates
//! without a cap, or shows a sniffed domain in `Debug` or in a log line.

mod hostname;
mod http;
mod quic;
mod stream;
mod tls;
mod wire;

#[cfg(test)]
pub(crate) mod testing;

use std::fmt;

pub use http::probe_http;
pub use quic::{QuicProgress, QuicSniffer, sniff_quic_datagram};
#[cfg(windows)]
pub(crate) use stream::sniff_stream_ready;
pub use stream::{SniffLimits, StreamSniff, sniff_stream};
pub use tls::probe_tls;

/// Application protocol recognised by the sniffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tls,
    Http,
    Quic,
}

/// A recognised protocol and, when the flow names one, its destination domain.
#[derive(Clone, PartialEq, Eq)]
pub struct Sniffed {
    pub protocol: Protocol,
    /// Lower-case host name without port or trailing dot. Never an IP literal.
    pub domain: Option<String>,
}

impl fmt::Debug for Sniffed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sniffed")
            .field("protocol", &self.protocol)
            .field("has_domain", &self.domain.is_some())
            .finish()
    }
}

/// Outcome of looking at the bytes buffered so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Found(Sniffed),
    NeedMore,
    NotThis,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffed_debug_hides_the_domain_name() {
        let with_domain = Sniffed {
            protocol: Protocol::Tls,
            domain: Some("secret.example.com".to_owned()),
        };
        let rendered = format!("{with_domain:?}");
        assert!(rendered.contains("Tls"));
        assert!(rendered.contains("has_domain: true"));
        assert!(!rendered.contains("example.com"));
        assert!(!rendered.contains("secret"));

        let without_domain = Sniffed {
            protocol: Protocol::Http,
            domain: None,
        };
        let rendered_none = format!("{without_domain:?}");
        assert!(rendered_none.contains("Http"));
        assert!(rendered_none.contains("has_domain: false"));
    }
}
