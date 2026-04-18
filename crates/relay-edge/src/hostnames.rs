//! Ephemeral hostname generator: `<adj>-<noun>-<4hex>.<temporary_domain>`.
//! See `DECISIONS.md` D5.

use rand::Rng;

use crate::wordlists::{ADJECTIVES, NOUNS};

pub fn generate_label() -> String {
    let mut rng = rand::thread_rng();
    let adj = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.gen_range(0..NOUNS.len())];
    let suffix: u16 = rng.r#gen();
    format!("{adj}-{noun}-{suffix:04x}")
}

pub fn generate_full(temporary_domain: &str) -> String {
    format!("{}.{}", generate_label(), temporary_domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_shape() {
        let l = generate_label();
        let parts: Vec<&str> = l.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2].len(), 4);
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
    }
}
