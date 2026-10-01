use std::net::IpAddr;
// validate an ip address.  we could use the same
pub fn ip_address(number: &str) -> bool {
    number.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_valid_number_limits() {
        assert!(ip_address("0.0.0.0"));
        assert!(ip_address("255.255.255.255"));
    }

    #[test]
    fn ipv4_valid_number() {
        assert!(ip_address("74.14.136.194"));
    }

    #[test]
    fn ipv4_invalid_not_enough_parts() {
        assert!(!ip_address("74.14.194"));
        assert!(!ip_address("74.14"));
        assert!(!ip_address("74"));
        assert!(!ip_address(""));
    }
    #[test]
    fn ipv4_invalid_number_too_big() {
        assert!(!ip_address("256.14.136.194"));
        assert!(!ip_address("74.256.136.194"));
        assert!(!ip_address("74.14.256.194"));
        assert!(!ip_address("74.14.136.256"));
    }

    #[test]
    fn test_ipv4_valid() {
        assert!(ip_address("192.168.1.1"));
        assert!(ip_address("10.0.0.1"));
        assert!(ip_address("0.0.0.0"));
        assert!(ip_address("255.255.255.255"));
        assert!(ip_address("172.16.254.3"));
    }

    #[test]
    fn test_ipv4_invalid() {
        assert!(!ip_address(""));
        assert!(!ip_address("256.1.1.1"));
        assert!(!ip_address("1.2.3"));
        assert!(!ip_address("1.2.3.4.5"));
        assert!(!ip_address("a.b.c.d"));
        assert!(!ip_address("1.2.3."));
        assert!(!ip_address("1..2.3"));
        assert!(!ip_address(" 1.2.3.4"));
    }

}