use crate::analysis::{Candidate, Evidence};
use crate::detector::DetectorKind;
use crate::pattern::Action;
use crate::source::Source;
use serde::Serialize;
use strum_macros::{Display, EnumString};

#[derive(EnumString, Display, Clone, Copy, Debug, Serialize)]
#[strum(serialize_all = "snake_case")]
pub enum FindingKind {
    None,
    Password,
    Email,
    IP,
    Name,
    Secret,
    Connection,
    CreditCard,
    Custom, // this is only turned on when a user has custom rules
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display, Hash, Serialize)]
#[strum(serialize_all = "snake_case")]
pub enum RuleSet {
    Pii,
    Secrets,
    Other,
}

impl FindingKind {
    pub fn set(&self) -> RuleSet {
        match self {
            FindingKind::Email | FindingKind::Name | FindingKind::CreditCard => RuleSet::Pii,
            FindingKind::Password | FindingKind::Secret | FindingKind::Connection => {
                RuleSet::Secrets
            }
            _ => RuleSet::Other,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub confidence: f64,
    pub action: Action,
    pub detector: DetectorKind,
    pub evidence: Vec<Evidence>,
    pub source: Source,
}

#[derive(Debug)]
pub struct FindingError {}
impl Finding {
    pub fn from_candidate(
        c: Candidate,
        action: Action,
        kind: FindingKind,
    ) -> Result<Self, FindingError> {
        Ok(Finding {
            kind: kind,
            confidence: c.confidence,
            action,
            detector: c.kind,
            evidence: c.evidence,
            source: c.source,
        })
    }
}
