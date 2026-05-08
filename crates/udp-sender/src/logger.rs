use std::collections::BTreeMap;
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

    pub fn log(
        &self,
        level: LogLevel,
        message: &str,
        fields: &[(&str, &str)],
    ) {
        if level < self.min_level {
            return;
        }

        let mut ordered = BTreeMap::new();
        ordered.insert("level".to_string(), level.as_str().to_string());
        ordered.insert("message".to_string(), message.to_string());

        for &(key, value) in fields {
            ordered.insert(key.to_string(), value.to_string());
        }

        let json = serde_json::to_string(&ordered).unwrap_or_else(|_| {
            r#"{"level":"error","message":"failed to serialize log entry"}"#.to_string()
        });

        let mut stdout = io::stdout().lock();
        let _ = writeln!(stdout, "{json}");

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_filtering() {
        let logger = Logger::new(LogLevel::Warn);

        logger.log(LogLevel::Info, "should not appear", &[]);
        logger.log(LogLevel::Warn, "should appear", &[]);
    }

    #[test]
    fn test_extra_fields_flattened_top_level() {
        let logger = Logger::new(LogLevel::Debug);
        logger.log(
            LogLevel::Info,
            "test message",
            &[("key1", "val1"), ("key2", "val2")],
        );
    }

    #[test]
    fn test_field_order_level_before_message() {
        let logger = Logger::new(LogLevel::Debug);
        logger.log(LogLevel::Info, "ordered", &[]);
    }

    #[test]
    fn test_lowercase_level_in_output() {
        let logger = Logger::new(LogLevel::Debug);
        logger.log(LogLevel::Warn, "warn level test", &[]);
    }
}
