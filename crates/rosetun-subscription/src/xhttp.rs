//! Xray's XHTTP `extra` options, checked field by field. Only the client options
//! Rosetun models are kept; any other key is dropped, and a known key with a
//! wrong type or out of its limits skips the node.

use std::ops::RangeInclusive;

use rosetun_config::{XhttpExtra, XhttpRange, XhttpXmux};
use serde_json::{Map, Value};

use crate::SkipReason;

const MAX_EXTRA_LENGTH: usize = 8 * 1024;

const PADDING_BYTES: RangeInclusive<u32> = 1..=65_536;
const MAX_EACH_POST_BYTES: RangeInclusive<u32> = 1..=16 * 1024 * 1024;
const MIN_POSTS_INTERVAL_MS: RangeInclusive<u32> = 0..=60_000;
const MAX_BUFFERED_POSTS: RangeInclusive<u32> = 1..=4_096;
const XMUX_CONNECTIONS: RangeInclusive<u32> = 0..=1_024;
const XMUX_REUSE: RangeInclusive<u32> = 0..=1_000_000;
const XMUX_REUSABLE_SECS: RangeInclusive<u32> = 0..=86_400;
const KEEP_ALIVE_SECS: RangeInclusive<i64> = -1..=3_600;

/// Parses `extra` as a link carries it: a JSON object in text.
pub(crate) fn parse_text(text: &str) -> Result<XhttpExtra, SkipReason> {
    if text.trim().is_empty() {
        return Ok(XhttpExtra::default());
    }
    if text.len() > MAX_EXTRA_LENGTH {
        return Err(SkipReason::InvalidXhttpExtra);
    }
    let value: Value = serde_json::from_str(text).map_err(|_| SkipReason::InvalidXhttpExtra)?;
    parse(&value)
}

pub(crate) fn parse(value: &Value) -> Result<XhttpExtra, SkipReason> {
    let object = value.as_object().ok_or(SkipReason::InvalidXhttpExtra)?;
    if object
        .get("downloadSettings")
        .is_some_and(|value| !value.is_null())
    {
        return Err(SkipReason::XhttpDownloadSettings);
    }

    let xmux = match object.get("xmux") {
        None | Some(Value::Null) => None,
        Some(value) => xmux(value.as_object().ok_or(SkipReason::InvalidXhttpExtra)?)?,
    };
    Ok(XhttpExtra {
        headers: headers(object.get("headers"))?,
        x_padding_bytes: range(object, "xPaddingBytes", PADDING_BYTES)?,
        no_grpc_header: flag(object, "noGRPCHeader")?,
        no_sse_header: flag(object, "noSSEHeader")?,
        sc_max_each_post_bytes: range(object, "scMaxEachPostBytes", MAX_EACH_POST_BYTES)?,
        sc_min_posts_interval_ms: range(object, "scMinPostsIntervalMs", MIN_POSTS_INTERVAL_MS)?,
        sc_max_buffered_posts: match integer(object, "scMaxBufferedPosts")? {
            0 => None,
            value => Some(within(value, &MAX_BUFFERED_POSTS)?),
        },
        xmux,
    })
}

fn xmux(object: &Map<String, Value>) -> Result<Option<XhttpXmux>, SkipReason> {
    let xmux = XhttpXmux {
        max_concurrency: range(object, "maxConcurrency", XMUX_CONNECTIONS)?,
        max_connections: range(object, "maxConnections", XMUX_CONNECTIONS)?,
        c_max_reuse_times: range(object, "cMaxReuseTimes", XMUX_REUSE)?,
        h_max_request_times: range(object, "hMaxRequestTimes", XMUX_REUSE)?,
        h_max_reusable_secs: range(object, "hMaxReusableSecs", XMUX_REUSABLE_SECS)?,
        h_keep_alive_period: match integer(object, "hKeepAlivePeriod")? {
            0 => None,
            value if KEEP_ALIVE_SECS.contains(&value) => Some(value),
            _ => return Err(SkipReason::InvalidXhttpExtra),
        },
    };
    // Xray refuses both limits together.
    if xmux.max_concurrency.is_some() && xmux.max_connections.is_some() {
        return Err(SkipReason::InvalidXhttpExtra);
    }
    Ok((xmux != XhttpXmux::default()).then_some(xmux))
}

fn headers(
    value: Option<&Value>,
) -> Result<std::collections::BTreeMap<String, String>, SkipReason> {
    let object = match value {
        None | Some(Value::Null) => return Ok(Default::default()),
        Some(value) => value.as_object().ok_or(SkipReason::InvalidXhttpExtra)?,
    };
    if object.len() > XhttpExtra::MAX_HEADERS {
        return Err(SkipReason::InvalidXhttpExtra);
    }
    object
        .iter()
        .map(|(name, value)| {
            let value = value.as_str().ok_or(SkipReason::InvalidXhttpExtra)?;
            // Xray takes the host from `host`, never from the headers.
            let valid = (1..=XhttpExtra::MAX_HEADER_LENGTH).contains(&name.len())
                && name.bytes().all(is_token_byte)
                && !name.eq_ignore_ascii_case("host")
                && value.len() <= XhttpExtra::MAX_HEADER_LENGTH
                && !value.chars().any(char::is_control);
            valid
                .then(|| (name.clone(), value.to_owned()))
                .ok_or(SkipReason::InvalidXhttpExtra)
        })
        .collect()
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn flag(object: &Map<String, Value>, key: &str) -> Result<bool, SkipReason> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(SkipReason::InvalidXhttpExtra),
    }
}

fn integer(object: &Map<String, Value>, key: &str) -> Result<i64, SkipReason> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(value) => value.as_i64().ok_or(SkipReason::InvalidXhttpExtra),
    }
}

fn within(value: i64, limits: &RangeInclusive<u32>) -> Result<u32, SkipReason> {
    u32::try_from(value)
        .ok()
        .filter(|value| limits.contains(value))
        .ok_or(SkipReason::InvalidXhttpExtra)
}

/// Xray's `Int32Range`: an integer or a `"from-to"` string, reordered so that
/// `from <= to`. Zero is how Xray spells "not set", so it maps to `None`.
fn range(
    object: &Map<String, Value>,
    key: &str,
    limits: RangeInclusive<u32>,
) -> Result<Option<XhttpRange>, SkipReason> {
    let (left, right) = match object.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(number)) => {
            let value = number
                .as_i64()
                .filter(|value| i32::try_from(*value).is_ok())
                .ok_or(SkipReason::InvalidXhttpExtra)?;
            (value, value)
        }
        Some(Value::String(text)) => {
            range_text(text.trim()).ok_or(SkipReason::InvalidXhttpExtra)?
        }
        Some(_) => return Err(SkipReason::InvalidXhttpExtra),
    };
    if left == 0 && right == 0 {
        return Ok(None);
    }
    let (from, to) = (left.min(right), left.max(right));
    Ok(Some(XhttpRange {
        from: within(from, &limits)?,
        to: within(to, &limits)?,
    }))
}

fn range_text(text: &str) -> Option<(i64, i64)> {
    if text.is_empty() {
        return Some((0, 0));
    }
    let number = |text: &str| text.parse::<i32>().ok().map(i64::from);
    if let Some(value) = number(text) {
        return Some((value, value));
    }
    // A leading minus belongs to the first number, as in Xray's ParseRangeString.
    let split = usize::from(text.starts_with('-'));
    let (left, right) = text[split..].split_once('-')?;
    Some((number(&text[..split + left.len()])?, number(right)?))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn range_of(value: Value) -> Result<Option<XhttpRange>, SkipReason> {
        let object = json!({ "value": value });
        range(object.as_object().unwrap(), "value", 0..=100)
    }

    #[test]
    fn ranges_follow_xray_int32_range() {
        let some = |from, to| Ok(Some(XhttpRange { from, to }));
        assert_eq!(range_of(json!(16)), some(16, 16));
        assert_eq!(range_of(json!("16-32")), some(16, 32));
        assert_eq!(range_of(json!("32-16")), some(16, 32));
        assert_eq!(range_of(json!("7")), some(7, 7));
        assert_eq!(range_of(json!(0)), Ok(None));
        assert_eq!(range_of(json!("")), Ok(None));
        for invalid in [
            json!(-1),
            json!("-5-10"),
            json!("1-101"),
            json!("1-2-3"),
            json!("a-b"),
            json!(1.5),
            json!(true),
            json!(4_294_967_296_i64),
        ] {
            assert_eq!(
                range_of(invalid.clone()),
                Err(SkipReason::InvalidXhttpExtra),
                "{invalid}"
            );
        }
    }

    #[test]
    fn known_fields_are_typed_and_unknown_ones_dropped() {
        let extra = parse(&json!({
            "headers": { "X-Example": "example-value" },
            "xPaddingBytes": "100-1000",
            "noGRPCHeader": true,
            "scMaxBufferedPosts": 30,
            "xmux": { "maxConcurrency": "16-32", "hKeepAlivePeriod": 0 },
            "xPaddingObfsMode": true,
            "unknownOption": { "nested": [1, 2, 3] },
        }))
        .unwrap();
        assert_eq!(extra.headers.len(), 1);
        assert_eq!(
            extra.x_padding_bytes,
            Some(XhttpRange {
                from: 100,
                to: 1000
            })
        );
        assert!(extra.no_grpc_header);
        assert!(!extra.no_sse_header);
        assert_eq!(extra.sc_max_buffered_posts, Some(30));
        let xmux = extra.xmux.unwrap();
        assert_eq!(xmux.max_concurrency, Some(XhttpRange { from: 16, to: 32 }));
        assert_eq!(xmux.h_keep_alive_period, None);
    }

    #[test]
    fn wrong_types_limits_and_download_settings_skip_the_node() {
        let too_many: Map<String, Value> = (0..=XhttpExtra::MAX_HEADERS)
            .map(|index| (format!("X-Header-{index}"), json!("value")))
            .collect();
        for (input, reason) in [
            (json!([]), SkipReason::InvalidXhttpExtra),
            (
                json!({ "headers": { "Host": "example.com" } }),
                SkipReason::InvalidXhttpExtra,
            ),
            (
                json!({ "headers": { "X-Bad": "a\r\nb" } }),
                SkipReason::InvalidXhttpExtra,
            ),
            (
                json!({ "headers": { "Bad Name": "value" } }),
                SkipReason::InvalidXhttpExtra,
            ),
            (
                json!({ "headers": { "X-Long": "a".repeat(257) } }),
                SkipReason::InvalidXhttpExtra,
            ),
            (
                json!({ "headers": too_many }),
                SkipReason::InvalidXhttpExtra,
            ),
            (
                json!({ "headers": { "X-Number": 1 } }),
                SkipReason::InvalidXhttpExtra,
            ),
            (
                json!({ "noSSEHeader": "true" }),
                SkipReason::InvalidXhttpExtra,
            ),
            (
                json!({ "xPaddingBytes": "0-100" }),
                SkipReason::InvalidXhttpExtra,
            ),
            (
                json!({ "scMaxBufferedPosts": -1 }),
                SkipReason::InvalidXhttpExtra,
            ),
            (json!({ "xmux": "16" }), SkipReason::InvalidXhttpExtra),
            (
                json!({ "xmux": { "maxConcurrency": 8, "maxConnections": 4 } }),
                SkipReason::InvalidXhttpExtra,
            ),
            (
                json!({ "downloadSettings": { "address": "192.0.2.5" } }),
                SkipReason::XhttpDownloadSettings,
            ),
        ] {
            assert_eq!(parse(&input), Err(reason), "{input}");
        }
        assert_eq!(parse_text("{not json"), Err(SkipReason::InvalidXhttpExtra));
        assert_eq!(parse_text(""), Ok(XhttpExtra::default()));
    }
}
