use std::path::Path;
use std::io::{self}; 
use serde::{Serialize, Deserialize};
use crate::pattern::Action;
use crate::detector::{CreditCardDetector, Detector, EmailDetector, IPv4Detector, IPv6Detector};
use crate::finding::{FindingKind};
use crate::rules::Rule;

// Add Serialize to your structs (alongside Deserialize)
#[derive(Serialize, Deserialize)]
struct Policy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rule: Vec<RuleDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    custom_rule: Vec<CustomRuleDef>,
}

#[derive(Serialize, Deserialize)]
pub struct RuleDef {
    id: String,
    enabled: bool,
    action: String,
    confidence: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replacement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keep_last: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keep_first: Option<usize>,
}   

#[derive(Serialize, Deserialize)]
struct CustomRuleDef {
    id: String,
    enabled: bool,
    pattern: String,
    action: String,
    #[serde(default)]
    replacement: Option<String>,
    #[serde(default)]
    keep_last: Option<usize>,
    #[serde(default)]
    keep_first: Option<usize>,
}
fn build_action(def: &RuleDef) -> Result<Action, String> {
    match def.action.as_str() {
        "redact" => {
            let label = def.replacement.as_deref().ok_or("redact requires 'replacement'")?;
            Ok(Action::Redact(label.to_string()))
        }
        "mask" => {
            let last = def.keep_last.unwrap_or(4);
            Ok(Action::Mask { keep_last: last })
        }
        "hash" => Ok(Action::Hash),
        "remove" => Ok(Action::Remove),
        "report" | "none" => Ok(Action::None),
        other => Err(format!("unknown action: {}", other)),
    }
}   

pub fn init_policy(path: &Path) -> io::Result<()> {
    let policy = default_policy();
    let toml_str = toml::to_string_pretty(&policy).expect("serialize");
    std::fs::write(path, toml_str)
}   

use strum::ParseError;

fn build_rule(def: &RuleDef) -> Result<Rule, String> {
    let kind: FindingKind = def.id.parse()
        .map_err(|e: ParseError| format!("unknown rule id '{}': {}", def.id, e))?;

    let detectors: Vec<Box<dyn Detector>> = match kind {
        FindingKind::CreditCard => vec![Box::new(CreditCardDetector::new())],
        FindingKind::Email => vec![Box::new(EmailDetector::new())],
        FindingKind::IP => vec![Box::new(IPv4Detector::new()),Box::new(IPv6Detector::new())],
        _ => Vec::new(),
    };

    let action = build_action(def)?;

    Ok(Rule {
        kind,
        minimum_confidence: 0.5, // or pull from the TOML if you add it
        action,
        detectors,
    })
}

pub fn load_policy(path: &Path) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(path)?;
    let policy: Policy = toml::from_str(&contents)?;

    let mut rules = Vec::new();
    for def in &policy.rule {
        if !def.enabled { continue; }
        rules.push(build_rule(def)?);
    }
    for def in &policy.custom_rule {
        if !def.enabled { continue; }
        // handle custom rules with regex patterns
    }
    Ok(rules)
}   


fn default_policy() -> Policy {
    Policy {
        rule: vec![
            RuleDef {
                id: "credit_card".into(),
                enabled: true,
                action: "mask".into(),
                confidence: 0.5,
                replacement: None,
                keep_last: Some(4),
                keep_first: None,
            },
            RuleDef {
                id: "email".into(),
                enabled: true,
                action: "redact".into(),
                confidence: 0.5,
                replacement: Some("EMAIL".into()),
                keep_last: None,
                keep_first: None,
            },
            RuleDef {
                id: "connection".into(),
                enabled: true,
                action: "report".into(),
                confidence: 0.5,
                replacement: None,
                keep_last: None,
                keep_first: None,
            },
            RuleDef {
                id: "ip".into(),
                enabled: true,
                action: "mask".into(),
                confidence: 0.5,
                replacement: None,
                keep_last: Some(3),
                keep_first: None,
            },
        ],
        custom_rule: vec![],
    }
}   