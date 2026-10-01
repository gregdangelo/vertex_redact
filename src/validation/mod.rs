/*
    This library is for all of you functional checks.
    These can only be updated with an application update whereas patterns have their own setup
*/
mod luhn;
mod iban;
mod ip_address;
mod http_auth;

use luhn::luhn_check;
use iban::iban_check;
use ip_address::ip_address;
use http_auth::bearer_token;
use http_auth::jwt_token;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Validator {
    None,
    Luhn,              // CC, SIN, IMEI
    Iban,              // mod 97
    IPv4,
    IPv6,
    JWT,
    Bearer,
    // Vin,               // weighted mod 11
    // PassPortMrz,       // ICAO 9303
    // SsnFormat,         // structural rules only
    // EmailFormat,
    // PhoneFormat,
    // ...
    // Future: Checksum, IBAN(?) etc
}

impl Validator {
    pub fn validate(&self, input: &str) -> bool {
        match self {
            Validator::Luhn => luhn_check(input),
            Validator::Iban => iban_check(input),
            Validator::IPv4 => ip_address(input),
            Validator::IPv6 => ip_address(input),
            Validator::JWT  => jwt_token(input),
            Validator::Bearer => bearer_token(input),
            Validator::None => true, // Always pass on no validation
            // other validators go here
        }
    }
}

// Helper function that all validators could use as needed
fn clean_num(num_str: &str) -> String {
    let s  = num_str.replace(|c: char| c == '-' || c == ' ',"");
    s
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_num_cc_clean() {
        assert_eq!(clean_num("4111111111111111"),"4111111111111111")
    }
    #[test]
    fn clean_num_cc_dashes() {
        assert_eq!(clean_num("4111-1111-1111-1111"),"4111111111111111")
    }
    #[test]
    fn clean_num_cc_spaces() {
        assert_eq!(clean_num("4111 1111 1111 1111"),"4111111111111111")
    }

}

/*
also: https://www.piicrawler.com/blog/regular-expressions-used-in-pii-scanning/
more: https://github.com/datumbrain/aws-macie-pii-confidential-regexes/blob/master/regex_list.csv

similar projects:
https://github.com/Jiansen/pii-vault
https://github.com/censgate/redact/blob/main/crates/redact-core/src/recognizers/pattern.rs
https://github.com/kadir/cloakrs
https://github.com/worka-ai/pii

strong checksums
| What | Algorithm | Notes |
|------|-----------|-------|
| IBAN | Mod 97 (ISO 7064) | Move first 4 chars to end, letters→digits, `result % 97 == 1`. Very common in financial logs. |
| Canadian SIN | Luhn | You're in CA — same algorithm as CC, trivial to add. |
| IMEI (device IDs) | Luhn | 15 digits, sometimes in hardware logs. |
| Passport MRZ | ICAO 9303 mod 10 | Two-line machine-readable zone; each line has a check digit. |
| VIN | Weighted checksum (ISO 3779) | 17 chars, weighted sum mod 11. |
| Brazilian CPF | Dual mod 11 | Two independent check digits. |
| Australian TFN | Weighted mod 11 | 9 digits. |
| Dutch BSN | Elfproef (mod 11) | 9 digits. |
| Polish PESEL | Weighted mod 10 | 11 digits. |

// format only
| What | Check | Notes |
|------|-------|-------|
| US SSN | Area ≠ 000/666/9xx, group ≠ 00, serial ≠ 0000 | No real checksum, but these rules eliminate most random digit strings. |
| UK NINO | Prefix constraints (not GG/XX/AA, etc.) | Format-only. |
| Email | RFC 5322 structural | Has `@`, valid TLD, no spaces. |
| Phone | E.164: `+` country code, 7–15 digits total | Catches random digit runs that aren't phones. |
| IPv4 | Octets 0–255, flag private/reserved ranges | `10.x`, `172.16.x`, `192.168.x` are internal — different sensitivity. |
| DOB | Valid calendar date, age 0–120 | Eliminates random 8-digit strings. |
| API keys / tokens | Known prefixes + length + charset | e.g. `sk-` for Stripe, `ghp_` for GitHub, `AKIA` for AWS. |
*/

/*
going to want an audit log of what was done:


2. Audit Log
The problem it solves: Compliance teams (HIPAA, GDPR, CMMC, PCI-DSS) don't just want PII removed — they want a record of what was removed, when, where, and by what rule. If there's a data breach, the audit log is your evidence that redaction was in place and functioning.

What to log per redaction event:

{
  "ts": "2026-09-03T14:22:01.482Z",
  "req_id": "a3f8c2e1",
  "route": "/api/patients",
  "client_ip": "10.0.1.44",
  "entity_type": "SSN",
  "rule_id": "ssn_us_9digit",
  "token": "[[PII:SSN:0002]]",
  "confidence": 1.0,
  "action": "redacted"
}

Design for your setup:

Aspect	Recommendation
Format	JSON Lines (one JSON object per line). Append-only.
Location	Local file on the proxy host. Rotate daily or at 250 MB.
Integrity	Append a SHA-256 hash chain (each line includes the hash of the previous line). Tamper-evident without needing a database.
What NOT to log	The original PII value. Log the token, not the value. This keeps the audit log itself PII-free.
Forwarding	Optional: forward audit events to your logging server as a separate stream (don't mix with the redacted request body).
Retention	Configurable. Default 90 days local. Enterprise buyers will want 1–7 years.
Performance	Write to an in-memory ring buffer, flush to disk every 100 events or 1 second. Don't block the proxy on disk I/O.

Why the hash chain matters: If someone (or a bug) modifies a past log entry, the chain breaks. Your buyer can verify integrity offline with a simple script. This is a big trust-builder in air-gapped environments where there's no central logging infrastructure to cross-reference against.


Per-request summary (recommended)
{
  "ts": "2026-09-03T14:22:01Z",
  "req_id": "a3f8c2e1",
  "route": "/api/patients",
  "client_ip": "10.0.1.44",
  "redactions": {
    "SSN": 3,
    "NAME": 5,
    "EMAIL": 1
  },
  "total_bytes_redacted": 247
}

One line per request. Your 2–5 MB log file with 200 PII hits becomes one audit line instead of 200.

Why this is enough for compliance
What an auditor actually needs to verify:

Redaction was active — timestamp + route proves it.
What types were caught — the counts by type.
Volume — total bytes redacted (shows it wasn't a no-op).
They do not need to know that line 47 of the body had an SSN and line 203 had a name. That's forensic detail, not compliance evidence.

When per-event detail would matter
A rule fires at low confidence (regex matched but you're not sure it's real PII).
A new/unknown pattern matched (you added a rule and want to see if it's over-matching).
A request was dropped/blocked due to PII policy.
For those edge cases, log the individual event. For the 99% case where your regex is deterministic and high-confidence, the summary is fine.

Practical implementation
// Per-request accumulator (in-memory, discarded after forward)
let mut redaction_counts: HashMap<&str, u32> = HashMap::new();

for match in body.find_all(rules) {
    *redaction_counts.entry(match.rule_type).or_insert(0) += 1;
    body.replace(match.span(), format!("[REDACTED_{}]", match.rule_type));
}

// After forward, write ONE audit line
audit_log.push(RequestAudit {
    ts: now(),
    req_id,
    route,
    client_ip,
    redactions: redaction_counts,
    total_bytes_redacted: sum_of_match_lengths,
});

No extra memory pressure, no per-match disk write, and your audit log stays small. One line per request is the right granularity for your use case.

*/