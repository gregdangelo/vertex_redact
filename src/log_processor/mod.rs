// use crate::CompiledPattern;
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::source::InputContext;
use crate::rules::Rule;
use crate::finding::Finding;

// fn redact_json(val: &mut serde_json::Value, patterns: &[CompiledPattern], key: &[u8; 32]) {
//     match val {
//         serde_json::Value::String(s) => {
//             for p in patterns {
//                 p.apply(s, key);
//             }
//         }
//         serde_json::Value::Object(map) => {
//             for (_, v) in map.iter_mut() {
//                 redact_json(v, patterns, key);
//             }
//         }
//         serde_json::Value::Array(arr) => {
//             for v in arr.iter_mut() {
//                 redact_json(v, patterns, key);
//             }
//         }
//         _ => {}Candidate
//     }
// }
/*
your-tool input.txt                  # plain text
your-tool input.json                  # JSON (auto-detect or --format)
your-tool data.csv --columns 2,5     # specific columns
tail -f app.log | your-tool           # stdin   
*/

#[allow(dead_code)]
fn derive_key(file_content: &[u8], machine_id: &str, time_bucket: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(file_content);
    h.update(machine_id.as_bytes());
    h.update(time_bucket.to_le_bytes());
    h.finalize().into()
}

#[allow(dead_code)]
/// 6-hour buckets: 0, 1, 2, 3 per day
fn current_bucket() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    (now / 6 / 3600) % 4  // 0–3, resets daily
}

// pub struct LogProcessor {
//     patterns: Vec<CompiledPattern>,
//     key: [u8; 32],
//     last_bucket: u64,
// }

// impl LogProcessor {
//     pub fn new(patterns: Vec<CompiledPattern>) -> Self {
//         // let file = std::fs::read("patterns.sig").unwrap();
//         let file: [u8; 32] = [0; 32];
//         // let machine = hostname::get().unwrap().to_string_lossy().to_string();
//         let machine = "bobbyJ";
//         let bucket = current_bucket();
//         let key = derive_key(&file, &machine, bucket);

//         LogProcessor { patterns, key, last_bucket: bucket }
//     }

//     fn maybe_rotate(&mut self) {
//         let bucket = current_bucket();
//         if bucket != self.last_bucket {
//             // let file = std::fs::read("patterns.sig").unwrap();
//             let file: [u8; 32] = [0; 32];
//             // let machine = hostname::get().unwrap().to_string_lossy().to_string();
//             let machine = "bobbyG";
//             self.key = derive_key(&file, &machine, bucket);
//             self.last_bucket = bucket;
//         }
//     }

//     pub fn process(&mut self, line: &str) -> String {
//         self.maybe_rotate();
//         let mut s = line.to_string();
//         for p in &self.patterns {
//             p.apply(&mut s, &self.key);
//         }
//         s
//     }
//     pub fn scanner(&mut self, line: &str) {
//         let s = line.to_string();
//         for p in &self.patterns {
//             p.scan(&s, &self.key);
//         }
//     }
// }

pub struct RuleProcessor {rules: Vec<Rule>}
impl RuleProcessor {
    pub fn new(rules: Vec<Rule>) -> Self {
        RuleProcessor{rules}
    }
    pub fn process(&mut self, input: &mut InputContext) -> (String, Vec<Finding>) {
        // InputContext
        let mut findings: Vec<Finding> = Vec::new();
        for rule in &self.rules {
            let c: Vec<Finding> = rule.run(input);
            findings.extend(c);
        };
        (input.text.clone() ,findings)
    }
    pub fn scanner(&mut self, input: &mut InputContext) -> Vec<Finding> {
        // InputContext
        let mut findings: Vec<Finding> = Vec::new();
        for rule in &self.rules {
            let c: Vec<Finding> = rule.run(input);
            findings.extend(c);
        }
        findings
    }
}