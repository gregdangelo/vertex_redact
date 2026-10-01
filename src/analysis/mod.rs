use serde::Serialize;
use std::collections::HashMap;
use std::fmt;

use crate::{
    detector::DetectorKind,
    finding::{Finding, RuleSet},
    source::Source,
};

#[derive(Debug, Serialize)]
pub struct Analysis {
    pub findings: Vec<Finding>,
    pub summary: HashMap<RuleSet, usize>,
}
impl Analysis {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            summary: HashMap::new(),
        }
    }
    pub fn summarize_findings(&mut self) {
        for f in &self.findings {
            *self.summary.entry(f.kind.set()).or_insert(0) += 1;
        }
        self.findings.clear(); // remove existing findings
    }

    // Todo I think we can do better than this
    pub fn summary(&self) {
        eprintln!("---------- Findings Summary ----------");
        for (kind, count) in &self.summary {
            eprintln!("{}: {}", kind, count)
        }
    }
}

impl fmt::Display for Analysis {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for finding in &self.findings {
            writeln!(f, "kind:{}", finding.kind)?;
            writeln!(f, "confidence:{:.2}", finding.confidence)?;
            writeln!(f, "detector:{}", finding.detector)?;
            writeln!(f, "action:{}", finding.action)?;
            writeln!(f, "source:{}", finding.source)?; // this looks terrible.  it just shows `source:Stdin` but we should show `line: 135 ...`
            writeln!(f, "evidence:")?;
            for ev in &finding.evidence {
                writeln!(f, "    - {}", ev.msg)?;
            }
        }
        Ok(())
    }
}

// enum Detector {
//     None,
//     Password,
//     Email,
//     Name,
//     Secret,
//     Connection,
//     CreditCard,
// }

/*

contextual:
Pattern
structural
entropy & character anaylsis

score = 0
if pattern_valid:            score += 30
if keyword_in_window:        score += 30
if structural_context:       score += 20
if entropy_above_threshold:  score += 20
*/

// impl Detector {
//     fn evaluate(self) -> i32 {
//         match self {
//             Detector::Email => 30,
//             Detector::CreditCard => 30,
//             Detector::None => -10,
//             _ => 0,
//         }
//     }
// }

/*
    Detector -> Candidate -> Context Enrichment -> Confidence -> Policy Decision -> Transform

*/

// TODO incorporate Field into evaluation
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum EvidenceKind {
    PatternMatched,
    Validated,
    Context,
    Field,
}
impl EvidenceKind {
    pub fn default(self) -> String {
        match self {
            EvidenceKind::PatternMatched => "data matched known patterns".to_string(),
            EvidenceKind::Validated => "data passed known validation".to_string(),
            EvidenceKind::Context => "surrounding context support".to_string(),
            EvidenceKind::Field => "field supports data".to_string(),
        }
    }
    pub fn negative(self) -> String {
        match self {
            EvidenceKind::PatternMatched => "data did matched known patterns".to_string(),
            EvidenceKind::Validated => "data did not pass known validation".to_string(),
            EvidenceKind::Context => "surrounding context does not support".to_string(),
            EvidenceKind::Field => "fields do not support data".to_string(),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub msg: String,
    pub kind: EvidenceKind,
}

impl fmt::Display for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

// this won't live here - just a reference - or maybe it will not 100% sure
#[derive(Clone)]
pub struct Candidate {
    pub start: usize,
    pub end: usize,
    pub kind: DetectorKind,
    pub confidence: f64,
    pub evidence: Vec<Evidence>,
    pub source: Source,
}
