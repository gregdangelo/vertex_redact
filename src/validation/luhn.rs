use crate::validation::clean_num;
// validate a cc number- this is pub for now but that should be removed once this gets built out
pub fn luhn_check(number: &str) -> bool {
    let num_str = clean_num(number);
    let mut sum = 0;
    let mut ints = num_str.chars().filter_map(|c| c.to_digit(10));
    let mut alternate = false;

    for i in ints.by_ref().rev() {
        let mut d = i;
        if alternate {
            d *= 2;
            if d > 9 { d -= 9 ;}
        }
        sum += d;
        alternate = !alternate
    }

    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_valid_number() {
        assert!(luhn_check("79927398713"));
    }

    #[test]
    fn luhn_invalid_number() {
        assert!(!luhn_check("79927398710"));
    }

    #[test]
    fn luhn_single_digit() {
        assert!(luhn_check("0"));
    }

    #[test]
    fn luhn_empty_string() {
        assert!(luhn_check("")); // sum is 0, 0 % 10 == 0
    }

    #[test]
    fn luhn_invalid_number_w_clean() {
        assert!(luhn_check("4111111111111111"));
    }

    #[test]
    fn luhn_invalid_number_w_dashes() {
        assert!(luhn_check("4111-1111-1111-1111"));
    }

    #[test]
    fn luhn_invalid_number_w_spaces() {
        assert!(luhn_check("4111 1111 1111 1111"));
    }
}