use crate::analysis::{Candidate, Evidence, EvidenceKind};
use crate::source::InputContext;
use crate::validation::Validator;
use regex::Regex;
use serde::Serialize;
use strum_macros::{Display, EnumString};

#[derive(EnumString, Debug, Display, Clone, Copy, PartialEq, Serialize)]
pub enum DetectorKind {
    Unknown,
    Password,
    Email,
    Name,
    Secret,
    DatabaseConnection,
    Connection,
    CreditCard,
    IP, //v4 and v6
}

pub trait Detector: Send + Sync {
    fn kind(&self) -> DetectorKind;
    fn detect(&self, input: &InputContext) -> Vec<Candidate>;
}

pub fn context_score(
    text: &str,
    keywords: &[&str],
    kind: EvidenceKind,
    e: &mut Vec<Evidence>,
) -> f64 {
    let lower = text.to_lowercase();
    if keywords.iter().any(|k| lower.contains(k)) {
        e.push(Evidence {
            msg: kind.clone().default(),
            kind,
        });
        0.1
    } else {
        0.0
    }
}

pub struct CreditCardDetector {
    regex: Regex,
    validator: Validator,
}
impl Detector for CreditCardDetector {
    fn kind(&self) -> DetectorKind {
        DetectorKind::CreditCard
    }
    fn detect(&self, input: &InputContext) -> Vec<Candidate> {
        self.regex
            .find_iter(&input.text)
            .map(|m| {
                let matched = m.as_str();
                let (confidence, evidence) = self.evaluate(matched, input);
                Candidate {
                    kind: self.kind(),
                    start: m.start(),
                    end: m.end(),
                    confidence: confidence,
                    evidence: evidence,
                    source: input.source.clone(),
                }
            })
            .collect()
    }
}
impl CreditCardDetector {
    pub fn new() -> Self {
        let regex: Regex =
            Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b").expect("valid regex");
        let v: Validator = Validator::Luhn;
        Self {
            regex,
            validator: v,
        }
    }
    // context should be the entire input context so that we can also look at `field`
    fn evaluate(&self, matched: &str, context: &InputContext) -> (f64, Vec<Evidence>) {
        let mut e: Vec<Evidence> = vec![Evidence {
            kind: EvidenceKind::PatternMatched,
            msg: EvidenceKind::PatternMatched.default(),
        }];
        let mut score: f64 = 0.5;

        if self.validator.validate(matched) {
            score += 0.3;
            e.push(Evidence {
                msg: EvidenceKind::Validated.default(),
                kind: EvidenceKind::Validated,
            });
        } else {
            //if it didn't pass the luhn is really a cc?  I guess it could be a mistyped one
            score -= 0.3;
            e.push(Evidence {
                msg: EvidenceKind::Validated.negative(),
                kind: EvidenceKind::Validated,
            });
        }

        let keywords = ["card", "cc", "credit", "cvc"];
        // Context keywords boost confidence
        score += context_score(&context.text, &keywords, EvidenceKind::Context, &mut e);
        score += context
            .field
            .as_deref()
            .map(|f| context_score(f, &keywords, EvidenceKind::Field, &mut e))
            .unwrap_or(0.0);

        // let lower = context.text.to_lowercase();
        // if lower.contains("card") || lower.contains("cc") || lower.contains("credit")  || lower.contains("cvc") {
        //     score += 0.1;
        //     e.push(Evidence { msg: EvidenceKind::Context.default() , kind: EvidenceKind::Context });
        // }
        // score += match &context.field {
        //     None => 0.0 ,
        //     Some(s) => {
        //         let lower = s.to_lowercase();
        //         let mut v: f64 = 0.0;
        //         if lower.contains("card") || lower.contains("cc") || lower.contains("credit")  || lower.contains("cvc") {
        //             v = 0.1;
        //             e.push(Evidence { msg: EvidenceKind::Context.default() , kind: EvidenceKind::Context });
        //         }
        //         v
        //     }
        // };

        // we should also check against test data: https://docs.stripe.com/testing?testing-method=card-numbers
        // or at least known prefixes

        (score.min(1.0), e)
    }
}

pub struct EmailDetector {
    regex: Regex,
}
impl Detector for EmailDetector {
    fn kind(&self) -> DetectorKind {
        DetectorKind::Email
    }
    fn detect(&self, input: &InputContext) -> Vec<Candidate> {
        println!("input {}", input.text.as_str());
        self.regex
            .find_iter(&input.text)
            .map(|m| {
                println!("found {}", m.as_str());
                let (confidence, evidence) = self.evaluate(&input);
                Candidate {
                    kind: self.kind(),
                    start: m.start(),
                    end: m.end(),
                    confidence: confidence,
                    evidence: evidence,
                    source: input.source.clone(),
                }
            })
            .collect()
    }
}
impl EmailDetector {
    pub fn new() -> Self {
        let regex: Regex =
            Regex::new(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z|]{2,6}\b").expect("valid regex");
        Self { regex }
    }
    fn evaluate(&self, context: &InputContext) -> (f64, Vec<Evidence>) {
        let mut e: Vec<Evidence> = vec![Evidence {
            kind: EvidenceKind::PatternMatched,
            msg: EvidenceKind::PatternMatched.default(),
        }];
        let mut score: f64 = 0.8;

        // Context keywords boost confidence
        let keywords = ["email", "e-mail"];
        score += context_score(&context.text, &keywords, EvidenceKind::Context, &mut e);
        score += context
            .field
            .as_deref()
            .map(|f| context_score(f, &keywords, EvidenceKind::Field, &mut e))
            .unwrap_or(0.0);

        (score.min(1.0), e)
    }
}

pub struct IPv4Detector {
    regex: Regex,
    validator: Validator,
}
impl Detector for IPv4Detector {
    fn kind(&self) -> DetectorKind {
        DetectorKind::IP
    }
    fn detect(&self, input: &InputContext) -> Vec<Candidate> {
        self.regex
            .find_iter(&input.text)
            .map(|m| {
                let matched = m.as_str();
                let (confidence, evidence) = self.evaluate(matched, &input.text);
                Candidate {
                    kind: self.kind(),
                    start: m.start(),
                    end: m.end(),
                    confidence: confidence,
                    evidence: evidence,
                    source: input.source.clone(),
                }
            })
            .collect()
    }
}
impl IPv4Detector {
    pub fn new() -> Self {
        // let regex: Regex = Regex::new(r"\b::(?:[0-9A-Fa-f]{0,4}:){0,5}[0-9A-Fa-f]{0,4}:(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").expect("valid regex");
        let regex: Regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").expect("valid regex");
        let v: Validator = Validator::IPv4;
        Self {
            regex,
            validator: v,
        }
    }
    fn evaluate(&self, matched: &str, context: &str) -> (f64, Vec<Evidence>) {
        let mut e: Vec<Evidence> = vec![Evidence {
            kind: EvidenceKind::PatternMatched,
            msg: EvidenceKind::PatternMatched.default(),
        }];
        let mut score: f64 = 0.5;

        if self.validator.validate(matched) {
            score += 0.3;
            e.push(Evidence {
                msg: EvidenceKind::Validated.default(),
                kind: EvidenceKind::Validated,
            });
        } else {
            score -= 0.3;
            e.push(Evidence {
                msg: EvidenceKind::Validated.negative(),
                kind: EvidenceKind::Validated,
            });
        }

        // Context keywords boost confidence
        let lower = context.to_lowercase();
        if lower.contains("ip") || lower.contains("i.p.") {
            score += 0.1;
            e.push(Evidence {
                msg: EvidenceKind::Context.default(),
                kind: EvidenceKind::Context,
            });
        }

        (score.min(1.0), e)
    }
}
pub struct IPv6Detector {
    regex: Regex,
    validator: Validator,
}
impl Detector for IPv6Detector {
    fn kind(&self) -> DetectorKind {
        DetectorKind::IP
    }
    fn detect(&self, input: &InputContext) -> Vec<Candidate> {
        self.regex
            .find_iter(&input.text)
            .map(|m| {
                let matched = m.as_str();
                let (confidence, evidence) = self.evaluate(matched, &input.text);
                Candidate {
                    kind: self.kind(),
                    start: m.start(),
                    end: m.end(),
                    confidence: confidence,
                    evidence: evidence,
                    source: input.source.clone(),
                }
            })
            .collect()
    }
}
impl IPv6Detector {
    pub fn new() -> Self {
        let regex: Regex = Regex::new(r"\b[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}\b|\b::(?:[0-9A-Fa-f]{0,4}:){0,5}[0-9A-Fa-f]{0,4}:(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").expect("valid regex");
        let v: Validator = Validator::IPv6;
        Self {
            regex,
            validator: v,
        }
    }
    fn evaluate(&self, matched: &str, context: &str) -> (f64, Vec<Evidence>) {
        let mut e: Vec<Evidence> = vec![Evidence {
            kind: EvidenceKind::PatternMatched,
            msg: EvidenceKind::PatternMatched.default(),
        }];
        let mut score: f64 = 0.5;

        if self.validator.validate(matched) {
            score += 0.3;
            e.push(Evidence {
                msg: EvidenceKind::Validated.default(),
                kind: EvidenceKind::Validated,
            });
        } else {
            score -= 0.3;
            e.push(Evidence {
                msg: EvidenceKind::Validated.negative(),
                kind: EvidenceKind::Validated,
            });
        }

        // Context keywords boost confidence
        let lower = context.to_lowercase();
        if lower.contains("ip") || lower.contains("i.p.") {
            score += 0.1;
            e.push(Evidence {
                msg: EvidenceKind::Context.default(),
                kind: EvidenceKind::Context,
            });
        }

        (score.min(1.0), e)
    }
}

#[cfg(test)]
mod tests {
    use crate::source::Source;
    use float_cmp::approx_eq;

    use super::*;

    #[test]
    fn email_detector() {
        let ed = EmailDetector::new();
        let src = Source::Stdin { line: 0 };
        let test_data = [
            (
                "Emtpy string",
                InputContext {
                    text: String::new(),
                    source: src.clone(),
                    field: None,
                },
                Vec::new(),
            ),
            (
                "Email only",
                InputContext {
                    text: "what about emtpy@string.com this".to_string(),
                    source: src.clone(),
                    field: None,
                },
                vec![Candidate {
                    start: 11,
                    end: 27,
                    kind: ed.kind(),
                    confidence: 0.8,
                    evidence: vec![Evidence {
                        msg: EvidenceKind::PatternMatched.default(),
                        kind: EvidenceKind::PatternMatched,
                    }],
                    source: src.clone(),
                }],
            ),
            (
                "Email with context",
                InputContext {
                    text: "what aboutyou email me emtpy@string.com this".to_string(),
                    source: src.clone(),
                    field: None,
                },
                vec![Candidate {
                    start: 23,
                    end: 39,
                    kind: ed.kind(),
                    confidence: 0.9,
                    evidence: vec![
                        Evidence {
                            msg: EvidenceKind::PatternMatched.default(),
                            kind: EvidenceKind::PatternMatched,
                        },
                        Evidence {
                            msg: EvidenceKind::Context.default(),
                            kind: EvidenceKind::Context,
                        },
                    ],
                    source: src.clone(),
                }],
            ),
            (
                "Email with field",
                InputContext {
                    text: "what about you message me emtpy@string.com this".to_string(),
                    source: src.clone(),
                    field: Some("email".to_string()),
                },
                vec![Candidate {
                    start: 26,
                    end: 42,
                    kind: ed.kind(),
                    confidence: 0.9,
                    evidence: vec![
                        Evidence {
                            msg: EvidenceKind::PatternMatched.default(),
                            kind: EvidenceKind::PatternMatched,
                        },
                        Evidence {
                            msg: EvidenceKind::Field.default(),
                            kind: EvidenceKind::Field,
                        },
                    ],
                    source: src.clone(),
                }],
            ),
        ];

        for (name, input, expected) in test_data {
            let candidates = ed.detect(&input);
            assert_eq!(
                candidates.len(),
                expected.len(),
                "name={:?} candiates={:?}, text={:?}",
                name,
                candidates.len(),
                input.text,
            );
            if candidates.len() == expected.len() && expected.len() > 0 {
                let c = candidates[0].clone();
                let ex = expected[0].clone();
                assert_eq!(c.confidence, ex.confidence);
                assert_eq!(c.kind, ex.kind);
                assert_eq!(c.source, ex.source);
                assert_eq!(c.start, ex.start);
                assert_eq!(c.end, ex.end);
                assert!(approx_eq!(f64, c.confidence, ex.confidence, epsilon = 1e-9));
                assert_eq!(c.evidence[0].kind, EvidenceKind::PatternMatched); // double check
                for (i, ev) in c.evidence.iter().enumerate() {
                    assert_eq!(ev.kind, ex.evidence[i].kind);
                }
            }
        }
    }
}
/*

Here are practical, non-AI methods for scoring confidence around a finding in a line of text, roughly in order of implementation ease:

1. Contextual keyword proximity
Check for related keywords within a fixed window (e.g., ±100–300 chars) of the match. This is exactly how Microsoft Purview does it: a bare pattern match gets Medium confidence; a pattern match plus a keyword like "password", "secret", "token", "api_key" nearby bumps it to High.  Define a small keyword list per finding type.

2. Pattern validation beyond regex
Don't just match shape — validate. Examples:

Email: DNS MX lookup on the domain (or check against a known-TLD list).
Credit card / ID: Luhn checksum.
Secret/token: expected length range + character-class check (e.g., AWS keys are 20-char alphanumeric, GitHub tokens start with ghp_).
3. Structural / syntactic context
Inspect the line's structure around the match:

Is it an assignment? (key = value, export VAR=..., "token": "...")
Is it in a comment? (lower confidence — likely example/placeholder)
Is it in a config file vs. a README vs. source code?
Is the value quoted? In a list? These are cheap string checks that meaningfully shift confidence.
4. Entropy & character analysis
For secrets specifically, compute Shannon entropy over the matched string. Real keys/tokens have high entropy; placeholders like YOUR_API_KEY_HERE or xxxx have low entropy. A simple threshold (e.g., entropy > 3.5 bits/char for a 20+ char string) is a good filter.

5. Composite weighted score
Combine the signals above into a single 0–100 score. A simple approach:

score = 0
if pattern_valid:            score += 30
if keyword_in_window:        score += 30
if structural_context:       score += 20
if entropy_above_threshold:  score += 20

Tune the weights per finding type. This gives you a clean confidence number you can threshold on (e.g., ≥70 = high, 40–69 = medium, <40 = low).

6. Negative signals (deduct points)

Value looks like a placeholder (example, test, placeholder, changeme)
Appears in a well-known public repo's example file
Repeated verbatim across many lines (likely a template)
Practical first-round recipe

Signal	Effort	Impact
Regex pattern + basic validation	Low	Catches obvious false positives
Keyword proximity (±100 chars)	Low	Biggest single confidence bump
Entropy check for secrets	Low	Filters placeholders
Structural context (assignment, comment, quotes)	Medium	Distinguishes real config from docs
Composite score with thresholds	Low	Gives you a single number to act on

This mirrors what production DLP tools do internally before any ML is involved. When you later add NER, it slots in as another signal in the composite (e.g., "found a person-name adjacent to an email → +10").
--------------------------------
Good baseline. Here's what to layer on top of each:

Email (regex → higher confidence)

Your regex is the pattern-match layer. The cheap next signals:

Domain sanity check — reject example.com, test.com, foo.bar, single-char TLDs, or anything matching a known placeholder list. This kills a lot of false positives from docs and tests.
Keyword proximity — "email", "contact", "notify", "to:", "from:", "reply-to" within ±50 chars bumps confidence.
Structural context — is it in an assignment (email = "..."), a config key ("email":), or just free text in a paragraph? Assignment/config = higher confidence than prose.
Negative signal — if the local part is obviously a placeholder (user@example.com, john.doe@company.com in a README), deduct.
You don't need DNS/MX for a first pass — it's slow and network-dependent. The domain-placeholder list + keyword proximity gets you 80% of the way.

Credit card (regex + Luhn → higher confidence)

Luhn passes ~1 in 10 random 16-digit strings, so you still have false positives. Add:

BIN prefix check — validate the first 6–8 digits against known card network ranges (Visa 4, Mastercard 51-55/2221-2720, Amex 34/37, Discover 6011/65). A small prefix table is enough for a first pass.
Length check — 13, 15 (Amex), 16, or 19 digits. Reject anything else.
Keyword proximity — "card", "cc", "cvv", "billing", "payment", "card_number" within ±100 chars.
Structural context — is it near a CVV/expiry? If you see MM/YY or a 3–4 digit number nearby, that's a strong co-occurrence signal.
Negative signal — all-same-digit runs (4444444444444444), sequential digits, or values that appear in many files (test fixtures).
Quick composite for each type

# Email
score = 30  # base: regex matched
if domain not in PLACEHOLDER_DOMAINS: score += 20
if keyword_in_window(line, match, EMAIL_KEYWORDS): score += 25
if in_assignment_or_config(line, match): score += 15
if local_part in KNOWN_PLACEHOLDERS: score -= 30

# Credit card
score = 30  # base: regex matched
if luhn_check(digits): score += 20
if bin_prefix_valid(digits): score += 15
if keyword_in_window(line, match, CC_KEYWORDS): score += 20
if cvv_or_expiry_nearby(line, match): score += 15
if is_sequential_or_repeated(digits): score -= 40

That gives you a clean per-type confidence without any ML. The keyword lists and placeholder lists are the only "data" you maintain, and they're small.

*/
