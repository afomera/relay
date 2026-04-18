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

/// Let CLI users pass a short label (e.g. `andrea` or `*.andrea`) instead
/// of the full FQDN. If `input` already looks like an FQDN (contains a dot
/// after any leading `*.`), it's returned as-is. Otherwise the base domain
/// is appended so `andrea` → `andrea.<base>` and `*.andrea` → `*.andrea.<base>`.
pub fn expand_hostname(input: &str, base_domain: &str) -> String {
    let rest = input.strip_prefix("*.").unwrap_or(input);
    if rest.contains('.') {
        input.to_string()
    } else if input.starts_with("*.") {
        format!("*.{rest}.{base_domain}")
    } else {
        format!("{rest}.{base_domain}")
    }
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

    #[test]
    fn expands_bare_label() {
        assert_eq!(expand_hostname("andrea", "example.com"), "andrea.example.com");
    }

    #[test]
    fn expands_wildcard_label() {
        assert_eq!(expand_hostname("*.andrea", "example.com"), "*.andrea.example.com");
    }

    #[test]
    fn preserves_fqdn() {
        assert_eq!(expand_hostname("andrea.example.com", "other.com"), "andrea.example.com");
        assert_eq!(expand_hostname("*.andrea.example.com", "other.com"), "*.andrea.example.com");
    }
}
