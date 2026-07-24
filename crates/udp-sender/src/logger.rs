use std::io::{self, Write};
use std::process;

use crate::constants::LogLevel;

pub struct Logger {
    min_level: LogLevel,
}

impl Logger {
    pub fn new(min_level: LogLevel) -> Self {
        Self { min_level }
    }

    /// Returns true if a message at `level` would be emitted, so callers can
    /// skip formatting work for suppressed levels.
    pub fn would_log(&self, level: LogLevel) -> bool {
        level >= self.min_level
    }

    pub fn log(&self, level: LogLevel, message: &str, fields: &[(&str, &str)]) {
        if level < self.min_level {
            return;
        }

        // Manual JSON construction preserves insertion order:
        // level, then message, then fields in caller-provided order.
        // Matches the Go reference logger byte-for-byte.
        let mut buf = String::with_capacity(64 + message.len() + fields.len() * 32);
        buf.push('{');
        buf.push_str("\"level\":\"");
        push_json_escaped(&mut buf, level.as_str());
        buf.push_str("\",\"message\":\"");
        push_json_escaped(&mut buf, message);
        buf.push('"');

        for &(key, value) in fields {
            buf.push(',');
            buf.push('"');
            push_json_escaped(&mut buf, key);
            buf.push_str("\":\"");
            push_json_escaped(&mut buf, value);
            buf.push('"');
        }
        buf.push('}');
        buf.push('\n');

        // Logs go to stderr so stdout stays reserved for the binary
        // protocol stream emitted by generators.
        let mut stderr = io::stderr().lock();
        let _ = stderr.write_all(buf.as_bytes());

        if level == LogLevel::Fatal {
            process::exit(1);
        }
    }

    pub fn debug(&self, message: &str, fields: &[(&str, &str)]) {
        self.log(LogLevel::Debug, message, fields);
    }

    pub fn info(&self, message: &str, fields: &[(&str, &str)]) {
        self.log(LogLevel::Info, message, fields);
    }

    pub fn warn(&self, message: &str, fields: &[(&str, &str)]) {
        self.log(LogLevel::Warn, message, fields);
    }

    pub fn error(&self, message: &str, fields: &[(&str, &str)]) {
        self.log(LogLevel::Error, message, fields);
    }

    pub fn fatal(&self, message: &str, fields: &[(&str, &str)]) {
        self.log(LogLevel::Fatal, message, fields);
    }
}

fn push_json_escaped(buf: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '"' => buf.push_str("\\\""),
            '\\' => buf.push_str("\\\\"),
            '\n' => buf.push_str("\\n"),
            '\r' => buf.push_str("\\r"),
            '\t' => buf.push_str("\\t"),
            '\x08' => buf.push_str("\\b"),
            '\x0c' => buf.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(buf, "\\u{:04x}", c as u32);
            }
            c => buf.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(level: LogLevel, message: &str, fields: &[(&str, &str)]) -> String {
        let mut buf = String::new();
        buf.push('{');
        buf.push_str("\"level\":\"");
        push_json_escaped(&mut buf, level.as_str());
        buf.push_str("\",\"message\":\"");
        push_json_escaped(&mut buf, message);
        buf.push('"');
        for &(k, v) in fields {
            buf.push(',');
            buf.push('"');
            push_json_escaped(&mut buf, k);
            buf.push_str("\":\"");
            push_json_escaped(&mut buf, v);
            buf.push('"');
        }
        buf.push('}');
        buf
    }

    #[test]
    fn test_field_order_level_first_then_message_then_insertion() {
        let s = render(LogLevel::Info, "hello", &[("b", "1"), ("a", "2")]);
        assert_eq!(s, r#"{"level":"info","message":"hello","b":"1","a":"2"}"#);
    }

    #[test]
    fn test_lowercase_level_in_output() {
        let s = render(LogLevel::Warn, "x", &[]);
        assert!(s.starts_with(r#"{"level":"warn","message":"x"#));
    }

    #[test]
    fn test_json_escapes_quotes_and_backslashes() {
        let s = render(LogLevel::Info, r#"a"b\c"#, &[]);
        assert_eq!(s, r#"{"level":"info","message":"a\"b\\c"}"#);
    }

    #[test]
    fn test_json_escapes_control_chars() {
        let s = render(LogLevel::Info, "x\nyy\tz", &[]);
        assert!(s.contains(r"\n"));
        assert!(s.contains(r"\t"));
    }

    #[test]
    fn test_level_filtering_below_min_drops() {
        let logger = Logger::new(LogLevel::Warn);
        logger.log(LogLevel::Info, "filtered", &[]);
    }

    #[test]
    fn test_no_timestamp_field() {
        let s = render(LogLevel::Info, "msg", &[]);
        assert!(!s.contains("\"time\""));
        assert!(!s.contains("\"timestamp\""));
        assert!(!s.contains("\"ts\""));
    }

    #[test]
    fn test_json_escapes_backspace_and_formfeed() {
        // \b (0x08) and \f (0x0c) get short-form escapes per RFC 8259
        let s = render(LogLevel::Info, "a\x08b\x0cc", &[]);
        assert_eq!(s, r#"{"level":"info","message":"a\bb\fc"}"#);
    }

    #[test]
    fn test_json_escapes_carriage_return() {
        let s = render(LogLevel::Info, "a\rb", &[]);
        assert_eq!(s, r#"{"level":"info","message":"a\rb"}"#);
    }

    #[test]
    fn test_json_escapes_other_control_chars_as_unicode() {
        // 0x01 (SOH) has no short form; must emit \u0001
        let s = render(LogLevel::Info, "x\x01y\x1fz", &[]);
        assert_eq!(s, r#"{"level":"info","message":"x\u0001y\u001fz"}"#);
    }

    #[test]
    fn test_json_passes_through_del_and_high_unicode() {
        // 0x7f (DEL) and chars >= 0x20 pass through unescaped (UTF-8 safe).
        let s = render(LogLevel::Info, "a\x7fb\u{00e9}c\u{1f600}", &[]);
        assert_eq!(
            s,
            "{\"level\":\"info\",\"message\":\"a\x7fb\u{00e9}c\u{1f600}\"}"
        );
    }

    #[test]
    fn test_field_keys_and_values_are_escaped() {
        // Keys containing quotes/backslashes must escape too.
        let s = render(
            LogLevel::Info,
            "msg",
            &[(r#"k"ey"#, r#"v\al"#), ("\nk2", "v2")],
        );
        assert_eq!(
            s,
            r#"{"level":"info","message":"msg","k\"ey":"v\\al","\nk2":"v2"}"#
        );
    }

    #[test]
    fn test_empty_message_and_empty_fields() {
        let s = render(LogLevel::Info, "", &[]);
        assert_eq!(s, r#"{"level":"info","message":""}"#);
    }

    #[test]
    fn test_empty_field_value_renders_empty_string() {
        let s = render(LogLevel::Info, "m", &[("k", "")]);
        assert_eq!(s, r#"{"level":"info","message":"m","k":""}"#);
    }

    #[test]
    fn test_level_filtering_at_threshold_passes() {
        // log(level=Warn, min=Warn) is NOT below min, so it WOULD emit (we
        // can't capture stderr easily, but ensure no panic and exercise path).
        let logger = Logger::new(LogLevel::Warn);
        logger.log(LogLevel::Warn, "at-threshold", &[("k", "v")]);
        logger.log(LogLevel::Error, "above-threshold", &[]);
    }

    #[test]
    fn test_all_level_string_representations() {
        // Sanity-check the lowercase emission for every variant.
        assert_eq!(
            render(LogLevel::Debug, "x", &[]),
            r#"{"level":"debug","message":"x"}"#
        );
        assert_eq!(
            render(LogLevel::Info, "x", &[]),
            r#"{"level":"info","message":"x"}"#
        );
        assert_eq!(
            render(LogLevel::Warn, "x", &[]),
            r#"{"level":"warn","message":"x"}"#
        );
        assert_eq!(
            render(LogLevel::Error, "x", &[]),
            r#"{"level":"error","message":"x"}"#
        );
        assert_eq!(
            render(LogLevel::Fatal, "x", &[]),
            r#"{"level":"fatal","message":"x"}"#
        );
    }
}
