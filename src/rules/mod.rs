pub mod policy;
use crate::analysis::Candidate;
use crate::detector::Detector;
use crate::finding::{Finding, FindingKind};
use crate::pattern::Action;
use crate::source::InputContext;

// #[derive(Debug)]
// pub struct RuleDefError{}

// impl TryFrom<RuleDef> for Rule {
//     type Error = RuleDefError;

//     fn try_from(def: RuleDef) -> Result<Self, Self::Error> {
//         let confidence: f32 = match def.confidence.parse() {
//             Ok(v) => v,
//             Err(_) => 0.0
//         };
//         let action: Action = match def.action.to_lowercase().as_str() {
//             "redact" => Action::Remove,
//             "mask" => Action::Remove,
//             "remove" => Action::Remove,
//             "hash" => Action::Remove,
//             "none" => Action::None,
//             _ => Action::None

//         };
//         let kind: FindingKind = match def.kind.to_lowercase().as_str() {
//             "none"    => FindingKind::None,
//             "custom"    => FindingKind::Custom,
//             "password"    => FindingKind::Password,
//             "email"    => FindingKind::Email,
//             "name"    => FindingKind::Name,
//             "secret"    => FindingKind::Secret,
//        init_policy     "connection"    => FindingKind::Connection,
//             "creditcard"    => FindingKind::CreditCard,
//             _ => FindingKind::None

//         };
//         Ok(Rule { kind:kind, minimum_confidence: confidence, action: action, detectors: Vec::new() })
//     }
// }

pub struct Rule {
    pub kind: FindingKind,
    pub minimum_confidence: f64,
    pub action: Action,
    pub detectors: Vec<Box<dyn Detector>>,
}

impl Rule {
    pub fn run(&self, input: &mut InputContext) -> Vec<Finding> {
        let key: [u8; 32] = [0; 32];
        let candidates: Vec<Candidate> = self
            .detectors
            .iter()
            .flat_map(|d| d.detect(input))
            .collect();
        let mut findings: Vec<Finding> = Vec::new();
        for c in candidates.iter().rev() {
            let f = if c.confidence >= self.minimum_confidence {
                self.action.apply(&mut input.text, c.start..c.end, &key);
                Finding::from_candidate(c.clone(), self.action.clone(), self.kind)
                    .expect("this to work")
            } else {
                Finding::from_candidate(c.clone(), Action::None, self.kind).expect("this to work")
            };
            findings.push(f);
        }
        findings
    }
}
