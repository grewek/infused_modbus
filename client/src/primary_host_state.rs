//! Parses a Sparkplug B Primary Host Application's `STATE` message payload —
//! unlike every other Sparkplug message, `STATE` is plain JSON
//! (`{"online":true,"timestamp":...}`), not protobuf, per spec. The shape is
//! small and fixed, so this hand-rolls a scan for the `"online"` key's
//! boolean value rather than pulling in a general-purpose JSON crate — the
//! same "from scratch for a bounded, well-known format" convention this
//! project already applies to Modbus PDUs and Sparkplug's own protobuf wire
//! format.

/// Returns the `online` field's boolean value, or `None` if the payload
/// isn't valid UTF-8, doesn't contain an `"online"` key, or that key isn't
/// followed by a recognizable `true`/`false` literal. Deliberately tolerant
/// of whitespace/key ordering (`{"timestamp":1,"online":true}` parses fine
/// too) since this only needs to answer one question, not validate the
/// payload's full shape.
pub fn parse_online(payload: &[u8]) -> Option<bool> {
    let text = std::str::from_utf8(payload).ok()?;
    let key_start = text.find("\"online\"")?;
    let after_key = &text[key_start + "\"online\"".len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?.trim_start();
    if after_colon.starts_with("true") {
        Some(true)
    } else if after_colon.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_online_true() {
        assert_eq!(
            parse_online(br#"{"online":true,"timestamp":1790840962030}"#),
            Some(true)
        );
    }

    #[test]
    fn parses_online_false() {
        assert_eq!(
            parse_online(br#"{"online":false,"timestamp":1790840962030}"#),
            Some(false)
        );
    }

    #[test]
    fn tolerates_whitespace_and_different_key_order() {
        assert_eq!(
            parse_online(br#"{ "timestamp" : 1 , "online" : true }"#),
            Some(true)
        );
    }

    #[test]
    fn returns_none_when_online_key_is_absent() {
        assert_eq!(parse_online(br#"{"timestamp":1790840962030}"#), None);
    }

    #[test]
    fn returns_none_for_invalid_utf8() {
        assert_eq!(parse_online(&[0xFF, 0xFE]), None);
    }

    #[test]
    fn returns_none_for_a_malformed_online_value() {
        assert_eq!(parse_online(br#"{"online":"yes"}"#), None);
    }
}
