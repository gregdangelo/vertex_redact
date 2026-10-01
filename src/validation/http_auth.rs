pub fn bearer_token(number: &str) -> bool {
    // Strip the "Bearer " prefix, check the token is reasonable
    let token = number.strip_prefix("Bearer ").unwrap_or(number);
    token.len() >= 16
}

pub fn jwt_token(number: &str) -> bool {
    // Must have exactly 2 dots splitting it into 3 segments
    let parts: Vec<&str> = number.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    // Each segment must be valid base64url and non-empty
    parts.iter().all(|p| {
        !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bearer_valid() {
        assert!(bearer_token("Bearer abc123def456ghi789"));
        assert!(bearer_token("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"));
        assert!(bearer_token("Bearer sk-1234567890abcdef"));
    }

    #[test]
    fn test_bearer_invalid() {
        assert!(!bearer_token("Bearer"));
        assert!(!bearer_token("Bearer abc"));          // too short
        assert!(!bearer_token("Bearer "));             // empty token
    }

    #[test]
    fn test_jwt_valid() {
        assert!(jwt_token("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"));
        assert!(jwt_token("eyJ.a.b"));                 // minimal but structurally valid
    }

    #[test]
    fn test_jwt_invalid() {
        assert!(!jwt_token("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"));   // only 2 segments
        assert!(!jwt_token("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U.extra")); // 4 segments
        assert!(!jwt_token("eyJhbGciOiJIUzI1NiJ9..dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")); // empty middle segment
        assert!(!jwt_token(""));
    }   
}