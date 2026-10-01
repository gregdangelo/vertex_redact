use std::fmt;
use sha2::{Sha256};
use hmac::{Hmac, Mac};
use serde::{Serialize};
use strum_macros::EnumString;

// Define the HMAC type
type HmacSha256 = Hmac<Sha256>;

#[derive(EnumString,Debug,Clone,Serialize)]
pub enum Action {
    None,
    Redact(String),
    Mask { keep_last: usize },//keep_first, keep_domain:bool <- maybe special case for email a****@domain.com?
    Hash,
    Remove,
    Psuedonymize
}

impl Action {
    pub fn apply(&self, s: &mut String,range: std::ops::Range<usize>, key: &[u8; 32]) {
        // grab the text before mutation
        let matched = s.get(range.clone()).unwrap_or("").to_string();

        let replacement = match self {
            Action::Redact(label) => format!("[REDACTED_{}]",label),
            Action::Mask { keep_last } => {
                let chars: Vec<char> = matched.chars().collect();
                let split = chars.len().saturating_sub(*keep_last);
                let mask = "*".repeat(split);
                let keep: String = chars[split..].iter().copied().collect();
                format!("{}{}", mask, keep)
            },
            // this is not actually used at the moment so we will ingore this unwrap
              Action::Hash => {
                let mut mac = HmacSha256::new_from_slice(key).unwrap();
                mac.update(matched.as_bytes());
                format!("{:x}", mac.finalize().into_bytes())
            },
            Action::Remove => String::new(),
            Action::None | _ => return, //Psuedonymize goes here
        };

        s.replace_range(range, &replacement)
    }
}
impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Action::Redact(label) => write!(f, "redact_{}", label),
            Action::Mask { keep_last } => write!(f, "mask_keep_last_{}", keep_last),
            Action::Hash => write!(f, "hash"),
            Action::Remove => write!(f, "remove"),
            Action::None | _ => write!(f, "none"),
        }
    }
}   

// pub fn load() -> Result<Vec<CompiledPattern>, PatternCompileError>{
//     let data = r#"[{
//         "id":"cc_basic",
//         "name":"Credit Card",
//         "tier":"Basic",
//         "regex":"\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b",
//         "validation":"none",
//         "action":"Mask"
//     },{
//         "id":"email_basic",
//         "name":"Email",
//         "tier":"Basic",
//         "regex":"\\b[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z|]{2,6}\\b",
//         "validation":"none",
//         "action":"Redact"
//     },{
//         "id":"aws_key",
//         "name":"AWS",
//         "tier":"Premium",
//         "regex":"\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b",
//         "validation":"none",
//         "action":"Remove"
//     },{
//         "id":"SSN",
//         "name":"SSN",
//         "tier":"Basic",
//         "regex":"\\b(00[1-9]|0[1-9][0-9]|[1-5][0-9]{2}|6[0-5][0-9]|66[0-57-9]|6[7-9][0-9]|[78][0-9]{2})-(0[1-9]|[1-9][0-9])-(000[1-9]|00[1-9][0-9]|0[1-9][0-9]{2}|[1-9][0-9]{3})\\b",
//         "validation":"none",
//         "action":"Hash"
//     }]"#;
//     let mut patterns : Vec<CompiledPattern> = Vec::new();
//     let v: Vec<PatternDef> = serde_json::from_str(data)?;
//     for p in v {
//         let pattern = CompiledPattern::try_from(p)?;
//         patterns.push(pattern)
//     }
    

//     Ok(patterns)
// }

/*
to detect
API keys
Bearer Tokens
JWTs
Private Keys
Password Fields
Database Urls
Cloud Credentials
Webhook Secrets
OAuth Tokens
Basic-auth Headers
SSH keys

IP Address - v4 check done
Government Identifiers
Postal Codes

psuedonymization

Summary report
Redaction counts by Rule
Optional Findings report

IPv6:
Quick sanity check on what this catches:

Input	Match?	Parser accepts?
2001:0db8:0000:0000:0000:0000:0000:0001	✓	✓
2001:db8::1	✓	✓
::1	✓	✓
fe80::1	✓	✓
::ffff:192.168.1.1	✓ (2nd alt)	✓
12:34:56 (time)	✓ (false positive)	✗ rejected
abc:def	✗ (only 1 colon)	—
*/