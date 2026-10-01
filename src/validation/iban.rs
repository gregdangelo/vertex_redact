// src/validation/iban.rs

pub fn iban_check(input: &str) -> bool {
    // Strip spaces, uppercase
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();

    // Must be 15–34 chars, start with 2 letters
    if cleaned.len() < 15 || cleaned.len() > 34 {
        return false;
    }
    if !cleaned.chars().take(2).all(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    // Move first 4 chars to the end
    // let rearranged = &cleaned[4..] & cleaned[..4]; // no implementation for `&str & str`
    let rearranged = format!("{}{}", &cleaned[4..], &cleaned[..4]);

    // Convert letters to digits (A=10, B=11, … Z=35)
    let numeric: String = rearranged
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                c.to_string()
            } else {
                (c as u8 - 55).to_string()
            }
        })
        .collect();

    // Mod 97 — chunk to avoid overflow
    let mut remainder = 0u32;
    for ch in numeric.chars() {
        remainder = (remainder * 10 + ch.to_digit(10).unwrap_or(0)) % 97;
    }

    remainder == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_iban() {
        assert!(iban_check("DE89 3704 0044 0532 0130 00"));
    }

    #[test]
    fn invalid_iban() {
        assert!(!iban_check("DE89 3704 0044 0532 0130 01"));
    }

    #[test]
    fn too_short() {
        assert!(!iban_check("DE8937"));
    }

    #[test]
    fn no_spaces() {
        assert!(iban_check("DE89370400440532013000"));
    }
}   