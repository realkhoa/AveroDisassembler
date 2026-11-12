//! Native signature engine (YARA-compatible subset).
//!
//! Avero embeds a small rule dialect so scanning needs **no Python, no YARA install, no
//! runtime downloads**:
//!
//! ```text
//! rule name {
//!   meta: description = "..." severity = "high" category = "packing"
//!   strings: $a = "text" [ASCII|WIDE|NOCASE]  $b = { 48 8B ?? 00 }
//!   condition: any of them | all of them | N of them | $a
//! }
//! ```
//!
//! This is intentionally a subset: no modules, regex or external files. Full YARA-X can be
//! plugged in later as a sidecar (MIT-compatible, but requires rustc >= 1.95 and pulls in
//! wasmtime — too heavy for the "fast, small binary" goal).

use std::fmt;

use crate::ir::Severity;

/// Embedded default ruleset (compiled into the binary).
pub const DEFAULT_RULES: &str = include_str!("../rules/avero-default.yar");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    Text {
        name: String,
        bytes: Vec<u8>,
        nocase: bool,
    },
    Hex {
        name: String,
        bytes: Vec<Option<u8>>,
    },
}

impl Pattern {
    pub fn name(&self) -> &str {
        match self {
            Pattern::Text { name, .. } | Pattern::Hex { name, .. } => name,
        }
    }

    /// First offset where this pattern matches, if any.
    pub fn find_first(&self, data: &[u8]) -> Option<usize> {
        match self {
            Pattern::Text { bytes, nocase, .. } => find_text(data, bytes, *nocase),
            Pattern::Hex { bytes, .. } => find_hex(data, bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    Any,
    All,
    Count(usize),
    Single(usize),
}

impl Condition {
    fn evaluate(&self, matches: &[bool]) -> bool {
        let matched = matches.iter().filter(|value| **value).count();
        match self {
            Condition::Any => matched > 0,
            Condition::All => !matches.is_empty() && matched == matches.len(),
            Condition::Count(required) => matched >= *required,
            Condition::Single(index) => matches.get(*index).copied().unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub patterns: Vec<Pattern>,
    pub condition: Condition,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_index: usize,
    pub matched_patterns: usize,
    pub first_offset: Option<usize>,
}

impl RuleSet {
    pub fn compile(source: &str) -> Result<RuleSet, String> {
        let cleaned = strip_comments(source);
        let mut parser = Parser::new(&cleaned);
        let mut rules = Vec::new();
        loop {
            parser.skip_ws();
            if parser.at_end() {
                break;
            }
            let keyword = parser.ident()?;
            if keyword != "rule" {
                return Err(format!("expected `rule`, found `{keyword}`"));
            }
            rules.push(parser.parse_rule()?);
        }
        if rules.is_empty() {
            return Err("no rules found".to_string());
        }
        Ok(RuleSet { rules })
    }

    pub fn for_artifact(_kind: crate::ir::Kind) -> &'static RuleSet {
        // Reserved for per-format rulesets later; currently one shared ruleset.
        default_set()
    }

    pub fn scan(&self, data: &[u8]) -> Vec<RuleMatch> {
        let mut results = Vec::new();
        for (rule_index, rule) in self.rules.iter().enumerate() {
            let mut matches = Vec::with_capacity(rule.patterns.len());
            let mut first_offset: Option<usize> = None;
            for pattern in &rule.patterns {
                let offset = pattern.find_first(data);
                matches.push(offset.is_some());
                if let Some(offset) = offset {
                    first_offset = Some(match first_offset {
                        Some(current) => current.min(offset),
                        None => offset,
                    });
                }
            }
            if rule.condition.evaluate(&matches) {
                results.push(RuleMatch {
                    rule_index,
                    matched_patterns: matches.iter().filter(|value| **value).count(),
                    first_offset,
                });
            }
        }
        results
    }
}

/// Lazily compiled embedded default ruleset.
pub fn default_ruleset() -> Result<&'static RuleSet, String> {
    static RULES: std::sync::OnceLock<Result<RuleSet, String>> = std::sync::OnceLock::new();
    match RULES.get_or_init(|| RuleSet::compile(DEFAULT_RULES)) {
        Ok(rules) => Ok(rules),
        Err(error) => Err(error.clone()),
    }
}

static DEFAULT: std::sync::OnceLock<RuleSet> = std::sync::OnceLock::new();

fn default_set() -> &'static RuleSet {
    DEFAULT.get_or_init(|| {
        RuleSet::compile(DEFAULT_RULES).unwrap_or_else(|_| RuleSet { rules: Vec::new() })
    })
}

// ------------------------------------------------------------------------------
// matching helpers
// ------------------------------------------------------------------------------

fn equals_byte(left: u8, right: u8, nocase: bool) -> bool {
    if nocase {
        left.to_ascii_lowercase() == right.to_ascii_lowercase()
    } else {
        left == right
    }
}

fn find_text(data: &[u8], needle: &[u8], nocase: bool) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > data.len() {
        return None;
    }
    let first = needle[0];
    let first = if nocase {
        first.to_ascii_lowercase()
    } else {
        first
    };
    for start in 0..=data.len() - needle.len() {
        let candidate = data[start];
        let candidate = if nocase {
            candidate.to_ascii_lowercase()
        } else {
            candidate
        };
        if candidate != first {
            continue;
        }
        let matched = needle
            .iter()
            .zip(&data[start..start + needle.len()])
            .all(|(expected, actual)| equals_byte(*actual, *expected, nocase));
        if matched {
            return Some(start);
        }
    }
    None
}

fn find_hex(data: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    if pattern.is_empty() {
        return Some(0);
    }
    let Some(anchor_index) = pattern.iter().position(|byte| byte.is_some()) else {
        return Some(0); // all wildcards: trivially matches at offset 0
    };
    let anchor = pattern[anchor_index].expect("anchor is Some");
    if pattern.len() > data.len() {
        return None;
    }
    for start in 0..=data.len() - pattern.len() {
        if data[start + anchor_index] != anchor {
            continue;
        }
        let matched = pattern
            .iter()
            .enumerate()
            .all(|(index, expected)| match expected {
                Some(expected) => data[start + index] == *expected,
                None => true,
            });
        if matched {
            return Some(start);
        }
    }
    None
}

// ------------------------------------------------------------------------------
// parser
// ------------------------------------------------------------------------------

/// Remove `//` and `/* ... */` comments while preserving string literals.
fn strip_comments(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut output = String::with_capacity(source.len());
    let mut index = 0usize;
    let mut in_string = false;
    while index < chars.len() {
        let current = chars[index];
        if in_string {
            output.push(current);
            if current == '\\' && index + 1 < chars.len() {
                output.push(chars[index + 1]);
                index += 2;
                continue;
            }
            if current == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if current == '"' {
            in_string = true;
            output.push(current);
            index += 1;
            continue;
        }
        if current == '/' && index + 1 < chars.len() {
            if chars[index + 1] == '/' {
                index += 2;
                while index < chars.len() && chars[index] != '\n' {
                    index += 1;
                }
                continue;
            }
            if chars[index + 1] == '*' {
                index += 2;
                while index + 1 < chars.len() && !(chars[index] == '*' && chars[index + 1] == '/') {
                    index += 1;
                }
                index += 2;
                continue;
            }
        }
        output.push(current);
        index += 1;
    }
    output
}

struct Parser<'a> {
    source: &'a str,
    position: usize,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Parser {
            source,
            position: 0,
        }
    }

    fn at_end(&self) -> bool {
        self.position >= self.source.len()
    }

    fn peek_char(&self) -> Option<char> {
        self.source[self.position..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let current = self.peek_char()?;
        self.position += current.len_utf8();
        Some(current)
    }

    fn skip_ws(&mut self) {
        while let Some(current) = self.peek_char() {
            if current.is_whitespace() {
                self.bump();
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), String> {
        self.skip_ws();
        match self.bump() {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(format!("expected `{expected}`, found `{actual}`")),
            None => Err(format!("expected `{expected}`, found end of input")),
        }
    }

    fn ident(&mut self) -> Result<String, String> {
        self.skip_ws();
        let mut output = String::new();
        while let Some(current) = self.peek_char() {
            if current.is_ascii_alphanumeric() || current == '_' || current == '.' || current == '-'
            {
                output.push(current);
                self.bump();
            } else {
                break;
            }
        }
        if output.is_empty() {
            Err("expected identifier".to_string())
        } else {
            Ok(output)
        }
    }

    fn string_literal(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut output = String::new();
        while let Some(current) = self.bump() {
            match current {
                '"' => return Ok(output),
                '\\' => {
                    let escaped = self.bump().ok_or("unterminated escape")?;
                    output.push(match escaped {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '\\' => '\\',
                        '"' => '"',
                        other => other,
                    });
                }
                other => output.push(other),
            }
        }
        Err("unterminated string literal".to_string())
    }

    fn parse_rule(&mut self) -> Result<Rule, String> {
        let name = self.ident()?;
        self.expect('{')?;
        let mut description = String::new();
        let mut severity = Severity::Info;
        let mut category = "signature".to_string();
        let mut patterns: Vec<Pattern> = Vec::new();
        let mut condition: Option<Condition> = None;

        loop {
            self.skip_ws();
            if self.peek_char() == Some('}') {
                self.bump();
                break;
            }
            let section = self.ident()?;
            match section.as_str() {
                "meta" => {
                    self.expect(':')?;
                    loop {
                        self.skip_ws();
                        if self.peek_char() == Some('}') || self.peek_ahead_is_section() {
                            break;
                        }
                        let key = self.ident()?;
                        self.expect('=')?;
                        self.skip_ws();
                        let value = self.meta_value()?;
                        match key.as_str() {
                            "description" => description = value,
                            "severity" => {
                                severity = match value.to_ascii_lowercase().as_str() {
                                    "critical" => Severity::Critical,
                                    "high" => Severity::High,
                                    "medium" => Severity::Medium,
                                    "low" => Severity::Low,
                                    _ => Severity::Info,
                                }
                            }
                            "category" => category = value,
                            _ => {}
                        }
                    }
                }
                "strings" => {
                    self.expect(':')?;
                    loop {
                        self.skip_ws();
                        if self.peek_char() == Some('}') || self.peek_ahead_is_section() {
                            break;
                        }
                        self.expect('$')?;
                        let pattern_name = self.ident()?;
                        self.expect('=')?;
                        self.skip_ws();
                        let pattern = match self.peek_char() {
                            Some('"') => self.parse_text_pattern(pattern_name)?,
                            Some('{') => self.parse_hex_pattern(pattern_name)?,
                            _ => return Err("expected string or hex pattern after `=`".to_string()),
                        };
                        patterns.push(pattern);
                        self.skip_ws();
                        if self.peek_char() == Some(';') {
                            self.bump();
                        }
                    }
                }
                "condition" => {
                    self.expect(':')?;
                    let raw = self.until_closing_brace()?;
                    condition = Some(parse_condition(&raw, &patterns)?);
                    self.expect('}')?;
                    break;
                }
                other => {
                    return Err(format!("unexpected section `{other}`"));
                }
            }
        }

        let condition = condition.ok_or_else(|| format!("rule `{name}` has no condition"))?;
        if patterns.is_empty() {
            return Err(format!("rule `{name}` has no patterns"));
        }
        Ok(Rule {
            name,
            description,
            severity,
            category,
            patterns,
            condition,
        })
    }

    fn peek_ahead_is_section(&mut self) -> bool {
        let saved = self.position;
        self.skip_ws();
        let result = self
            .ident()
            .map(|word| matches!(word.as_str(), "meta" | "strings" | "condition"))
            .unwrap_or(false)
            && {
                self.skip_ws();
                self.peek_char() == Some(':')
            };
        self.position = saved;
        result
    }

    fn meta_value(&mut self) -> Result<String, String> {
        self.skip_ws();
        if self.peek_char() == Some('"') {
            return self.string_literal();
        }
        let mut output = String::new();
        while let Some(current) = self.peek_char() {
            if current.is_whitespace() || current == '}' {
                break;
            }
            output.push(current);
            self.bump();
        }
        if output.is_empty() {
            Err("expected meta value".to_string())
        } else {
            Ok(output)
        }
    }

    fn parse_text_pattern(&mut self, name: String) -> Result<Pattern, String> {
        let literal = self.string_literal()?;
        let mut wide = false;
        let mut nocase = false;
        loop {
            let saved = self.position;
            self.skip_ws();
            if self.peek_char() == Some(';') || self.peek_char() == Some('}') {
                self.position = saved;
                break;
            }
            if self.peek_ahead_is_section() {
                self.position = saved;
                break;
            }
            let word = match self.ident() {
                Ok(word) => word,
                Err(_) => {
                    self.position = saved;
                    break;
                }
            };
            match word.to_ascii_lowercase().as_str() {
                "wide" => wide = true,
                "nocase" => nocase = true,
                "ascii" | "fullword" => {}
                _ => {
                    self.position = saved;
                    break;
                }
            }
        }
        let mut bytes = literal.into_bytes();
        if wide {
            let mut widened = Vec::with_capacity(bytes.len() * 2);
            for byte in bytes {
                widened.push(byte);
                widened.push(0);
            }
            bytes = widened;
        }
        Ok(Pattern::Text {
            name,
            bytes,
            nocase,
        })
    }

    fn parse_hex_pattern(&mut self, name: String) -> Result<Pattern, String> {
        self.expect('{')?;
        let mut bytes = Vec::new();
        loop {
            self.skip_ws();
            match self.peek_char() {
                Some('}') => {
                    self.bump();
                    break;
                }
                None => return Err("unterminated hex pattern".to_string()),
                _ => {}
            }
            let mut token = String::new();
            while let Some(current) = self.peek_char() {
                if current.is_whitespace() || current == '}' {
                    break;
                }
                token.push(current);
                self.bump();
            }
            if token.is_empty() {
                continue;
            }
            if token.len() != 2 {
                return Err(format!("unsupported hex token `{token}`"));
            }
            if token == "??" || token == "?" {
                bytes.push(None);
                continue;
            }
            if token.contains('?') {
                return Err(format!("partial wildcard `{token}` not supported"));
            }
            let value = u8::from_str_radix(&token, 16)
                .map_err(|_| format!("invalid hex byte `{token}`"))?;
            bytes.push(Some(value));
        }
        Ok(Pattern::Hex { name, bytes })
    }

    fn until_closing_brace(&mut self) -> Result<String, String> {
        let start = self.position;
        let mut index = self.position;
        while index < self.source.len() {
            if self.source[index..].starts_with('}') {
                let raw = self.source[start..index].trim().to_string();
                self.position = index;
                return Ok(raw);
            }
            index += self.source[index..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
        }
        Err("unterminated condition".to_string())
    }
}

fn parse_condition(raw: &str, patterns: &[Pattern]) -> Result<Condition, String> {
    let normalized = raw
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return Err("empty condition".to_string());
    }
    if normalized == "any of them" {
        return Ok(Condition::Any);
    }
    if normalized == "all of them" {
        return Ok(Condition::All);
    }
    if let Some(rest) = normalized.strip_suffix(" of them") {
        if let Ok(count) = rest.trim().parse::<usize>() {
            return Ok(Condition::Count(count));
        }
    }
    if let Some(pattern_name) = normalized.strip_prefix('$') {
        let pattern_name = pattern_name.trim();
        let index = patterns
            .iter()
            .position(|pattern| pattern.name() == pattern_name)
            .ok_or_else(|| format!("condition references unknown pattern `${pattern_name}`"))?;
        return Ok(Condition::Single(index));
    }
    Err(format!("unsupported condition: `{raw}`"))
}

impl fmt::Display for Rule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} ({} patterns, severity={})",
            self.name,
            self.patterns.len(),
            self.severity.as_str()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = r#"
        rule hello_world {
            meta:
                description = "hello test"
                severity = "medium"
                category = "test"
            strings:
                $a = "hello" ascii
                $b = "world" ascii
            condition:
                2 of them
        }
    "#;

    #[test]
    fn compiles_and_matches() {
        let rules = RuleSet::compile(SIMPLE).expect("rules compile");
        assert_eq!(rules.rules.len(), 1);
        assert_eq!(rules.rules[0].severity, Severity::Medium);
        let matches = rules.scan(b"\x00hello world\x00");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_patterns, 2);
        assert_eq!(matches[0].first_offset, Some(1));
        assert!(rules.scan(b"hello only").is_empty());
    }

    #[test]
    fn hex_wildcards_and_wide_and_nocase() {
        let source = r#"
            rule hex_rule {
                meta:
                    severity = "high"
                strings:
                    $a = { 48 8B ?? 00 }
                condition:
                    $a
            }
            rule wide_rule {
                meta:
                    severity = "low"
                strings:
                    $a = "Evil" wide nocase
                condition:
                    any of them
            }
        "#;
        let rules = RuleSet::compile(source).expect("compile");
        assert_eq!(rules.scan(&[0x48, 0x8B, 0xCC, 0x00]).len(), 1);
        assert!(rules.scan(&[0x48, 0x8B, 0xCC, 0x01]).is_empty());
        let wide: Vec<u8> = "evil"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let matches = rules.scan(&wide);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_index, 1);
    }

    #[test]
    fn default_rules_compile() {
        let ruleset = default_ruleset().expect("embedded rules must compile");
        assert!(
            ruleset.rules.len() >= 10,
            "expected a useful default ruleset"
        );
        let hits = ruleset.scan(b"MZ UPX0 UPX1 UPX!");
        assert!(hits
            .iter()
            .any(|hit| ruleset.rules[hit.rule_index].name == "upx_packer"));
    }

    #[test]
    fn comments_and_unknown_condition_are_handled() {
        let rules = RuleSet::compile(
            r#"
            // line comment
            rule commented {
                /* block comment */
                strings:
                    $a = "x"
                condition:
                    any of them
            }
        "#,
        )
        .expect("compile");
        assert!(rules.scan(b"x").len() == 1);
        let error = RuleSet::compile("rule bad { strings: $a = \"x\" condition: $a and $b }")
            .expect_err("unsupported condition must error");
        assert!(error.to_lowercase().contains("condition"));
    }
}
