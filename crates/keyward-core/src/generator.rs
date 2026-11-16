//! Password and passphrase generation with entropy estimates.
//!
//! All randomness comes from `OsRng`; characters and words are picked with
//! `rand`'s uniform sampling (no modulo bias).

use std::fmt;
use std::sync::LazyLock;

use rand::Rng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{}~";
/// Characters easily confused with each other in many fonts.
const AMBIGUOUS: &str = "Il1O0o";

/// Maximum password length accepted by the generator.
pub const MAX_LENGTH: usize = 1024;
/// Maximum number of passphrase words.
pub const MAX_WORDS: usize = 64;

static WORDLIST: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| include_str!("eff_large_wordlist.txt").lines().collect());

/// Size of the embedded EFF large wordlist.
pub fn wordlist_len() -> usize {
    WORDLIST.len()
}

/// Estimated entropy in bits (assuming the attacker knows the options).
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct EntropyBits(pub f64);

/// Rough strength band for display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    /// < 50 bits
    Weak,
    /// 50–70 bits
    Fair,
    /// 70–100 bits
    Strong,
    /// ≥ 100 bits
    VeryStrong,
}

impl EntropyBits {
    /// Strength band.
    pub fn strength(self) -> Strength {
        match self.0 {
            b if b < 50.0 => Strength::Weak,
            b if b < 70.0 => Strength::Fair,
            b if b < 100.0 => Strength::Strong,
            _ => Strength::VeryStrong,
        }
    }
}

impl fmt::Display for EntropyBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.1} bits", self.0)
    }
}

impl fmt::Display for Strength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Weak => "weak",
            Self::Fair => "fair",
            Self::Strong => "strong",
            Self::VeryStrong => "very strong",
        })
    }
}

/// Options for random-character passwords.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CharsetOptions {
    /// Number of characters.
    pub length: usize,
    /// Include a–z.
    pub lower: bool,
    /// Include A–Z.
    pub upper: bool,
    /// Include 0–9.
    pub digits: bool,
    /// Include punctuation.
    pub symbols: bool,
    /// Drop look-alike characters (`Il1O0o`).
    pub exclude_ambiguous: bool,
}

impl Default for CharsetOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

impl CharsetOptions {
    /// The enabled character classes, each already filtered for ambiguity.
    fn classes(&self) -> Vec<Vec<char>> {
        [
            (self.lower, LOWER),
            (self.upper, UPPER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, set)| {
            set.chars()
                .filter(|c| !(self.exclude_ambiguous && AMBIGUOUS.contains(*c)))
                .collect()
        })
        .collect()
    }

    /// Entropy of a uniformly random string over the pool that is
    /// conditioned on containing every class:
    /// `log2(#valid strings)` where #valid is computed by inclusion–exclusion.
    pub fn entropy(&self) -> Result<EntropyBits> {
        let classes = self.validate()?;
        let pool: usize = classes.iter().map(Vec::len).sum();
        let n = self.length as f64;
        // fraction of pool^n strings that contain every class
        let k = classes.len();
        let mut fraction = 0.0f64;
        for mask in 0u32..(1 << k) {
            let missing: usize = (0..k)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| classes[i].len())
                .sum();
            let term = ((pool - missing) as f64 / pool as f64).powf(n);
            if mask.count_ones() % 2 == 0 {
                fraction += term;
            } else {
                fraction -= term;
            }
        }
        let fraction = fraction.max(f64::MIN_POSITIVE);
        Ok(EntropyBits(n * (pool as f64).log2() + fraction.log2()))
    }

    fn validate(&self) -> Result<Vec<Vec<char>>> {
        let classes = self.classes();
        if classes.is_empty() {
            return Err(Error::InvalidGeneratorOptions(
                "enable at least one character class",
            ));
        }
        if self.length == 0 || self.length > MAX_LENGTH {
            return Err(Error::InvalidGeneratorOptions(
                "length must be between 1 and 1024",
            ));
        }
        if self.length < classes.len() {
            return Err(Error::InvalidGeneratorOptions(
                "length is shorter than the number of required character classes",
            ));
        }
        Ok(classes)
    }
}

/// Generate a random password containing at least one character from every
/// enabled class (by rejection sampling, which keeps the result uniform over
/// all valid strings).
pub fn generate_password(opts: &CharsetOptions) -> Result<(SecretString, EntropyBits)> {
    let classes = opts.validate()?;
    let pool: Vec<char> = classes.iter().flatten().copied().collect();
    let entropy = opts.entropy()?;
    loop {
        let mut out = Zeroizing::new(String::with_capacity(opts.length));
        for _ in 0..opts.length {
            out.push(*pool.choose(&mut OsRng).expect("pool is non-empty"));
        }
        if classes
            .iter()
            .all(|class| out.chars().any(|c| class.contains(&c)))
        {
            return Ok((SecretString::from(out.as_str().to_owned()), entropy));
        }
    }
}

/// Options for diceware-style passphrases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    /// Number of words.
    pub words: usize,
    /// Separator between words.
    pub separator: String,
    /// Capitalise the first letter of each word (adds no entropy).
    pub capitalize: bool,
    /// Append one random digit to one random word.
    pub add_digit: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".into(),
            capitalize: false,
            add_digit: false,
        }
    }
}

impl PassphraseOptions {
    /// `words · log2(7776)` (+ `log2(10 · words)` for the digit).
    pub fn entropy(&self) -> Result<EntropyBits> {
        self.validate()?;
        let w = self.words as f64;
        let mut bits = w * (WORDLIST.len() as f64).log2();
        if self.add_digit {
            bits += (10.0 * w).log2();
        }
        Ok(EntropyBits(bits))
    }

    fn validate(&self) -> Result<()> {
        if self.words == 0 || self.words > MAX_WORDS {
            return Err(Error::InvalidGeneratorOptions(
                "word count must be between 1 and 64",
            ));
        }
        if self.separator.chars().count() > 8 {
            return Err(Error::InvalidGeneratorOptions(
                "separator longer than 8 characters",
            ));
        }
        Ok(())
    }
}

/// Generate a passphrase from the EFF large wordlist.
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<(SecretString, EntropyBits)> {
    let entropy = opts.entropy()?;
    let digit_at = opts
        .add_digit
        .then(|| (OsRng.gen_range(0..opts.words), OsRng.gen_range(0..10u8)));
    // Reserve the worst case up front so the buffer never reallocates
    // (a reallocation would free a partial passphrase without zeroizing it).
    let max_word = WORDLIST.iter().map(|w| w.len()).max().unwrap_or(0);
    let mut out = Zeroizing::new(String::with_capacity(
        opts.words * (max_word + 1 + opts.separator.len()),
    ));
    for i in 0..opts.words {
        if i > 0 {
            out.push_str(&opts.separator);
        }
        let word = WORDLIST.choose(&mut OsRng).expect("wordlist is non-empty");
        let mut chars = word.chars();
        if opts.capitalize
            && let Some(first) = chars.next()
        {
            out.extend(first.to_uppercase());
        }
        out.push_str(chars.as_str());
        if let Some((pos, d)) = digit_at
            && pos == i
        {
            out.push(char::from(b'0' + d));
        }
    }
    Ok((SecretString::from(out.as_str().to_owned()), entropy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::collections::HashSet;

    #[test]
    fn wordlist_is_the_eff_large_list() {
        assert_eq!(WORDLIST.len(), 7776);
        let unique: HashSet<_> = WORDLIST.iter().collect();
        assert_eq!(unique.len(), 7776);
        assert!(
            WORDLIST
                .iter()
                .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        );
        assert_eq!(WORDLIST[0], "abacus");
        assert_eq!(WORDLIST[7775], "zoom");
    }

    #[test]
    fn password_has_length_and_every_class() {
        let o = CharsetOptions {
            length: 4,
            ..Default::default()
        };
        for _ in 0..200 {
            let (p, _) = generate_password(&o).unwrap();
            let p = p.expose_secret();
            assert_eq!(p.chars().count(), 4);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn respects_disabled_classes_and_ambiguity() {
        let o = CharsetOptions {
            length: 64,
            lower: true,
            upper: true,
            digits: true,
            symbols: false,
            exclude_ambiguous: true,
        };
        for _ in 0..50 {
            let (p, _) = generate_password(&o).unwrap();
            assert!(
                p.expose_secret()
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() && !AMBIGUOUS.contains(c))
            );
        }
    }

    #[test]
    fn invalid_options_are_rejected() {
        let none = CharsetOptions {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(generate_password(&none).is_err());
        let short = CharsetOptions {
            length: 3,
            ..Default::default()
        };
        assert!(generate_password(&short).is_err());
        let zero = CharsetOptions {
            length: 0,
            ..Default::default()
        };
        assert!(generate_password(&zero).is_err());
        assert!(
            generate_passphrase(&PassphraseOptions {
                words: 0,
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn entropy_matches_closed_form() {
        // single class: exactly length * log2(pool)
        let digits = CharsetOptions {
            length: 10,
            lower: false,
            upper: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!((digits.entropy().unwrap().0 - 10.0 * 10f64.log2()).abs() < 1e-9);

        // two classes, length 2, pools 26+10: valid = 2*26*10 = 520
        let two = CharsetOptions {
            length: 2,
            lower: true,
            digits: true,
            upper: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!((two.entropy().unwrap().0 - 520f64.log2()).abs() < 1e-9);

        // the requirement costs a little entropy versus the naive estimate
        let d = CharsetOptions::default();
        let naive = 20.0 * ((26 + 26 + 10 + SYMBOLS.len()) as f64).log2();
        let e = d.entropy().unwrap().0;
        assert!(e < naive && e > naive - 1.0, "{e} vs {naive}");
        assert_eq!(d.entropy().unwrap().strength(), Strength::VeryStrong);
    }

    #[test]
    fn passphrase_shape_and_entropy() {
        let o = PassphraseOptions {
            words: 5,
            separator: ".".into(),
            capitalize: true,
            add_digit: true,
        };
        let (p, e) = generate_passphrase(&o).unwrap();
        let p = p.expose_secret();
        let parts: Vec<_> = p.split('.').collect();
        assert_eq!(parts.len(), 5);
        assert!(
            parts
                .iter()
                .all(|w| w.starts_with(|c: char| c.is_uppercase()))
        );
        assert_eq!(p.chars().filter(char::is_ascii_digit).count(), 1);
        let expected = 5.0 * 7776f64.log2() + 50f64.log2();
        assert!((e.0 - expected).abs() < 1e-9);
        assert!((PassphraseOptions::default().entropy().unwrap().0 - 77.548).abs() < 0.01);
    }

    /// χ² goodness-of-fit over digits. The 99.999th percentile of χ²(9) is
    /// ~37.3, so this fails spuriously about once in 100 000 runs.
    #[test]
    fn character_distribution_is_uniform() {
        let o = CharsetOptions {
            length: 1000,
            lower: false,
            upper: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        let mut counts = [0u32; 10];
        for _ in 0..100 {
            let (p, _) = generate_password(&o).unwrap();
            for c in p.expose_secret().bytes() {
                counts[usize::from(c - b'0')] += 1;
            }
        }
        let expected = 100_000.0 / 10.0;
        let chi2: f64 = counts
            .iter()
            .map(|&c| (f64::from(c) - expected).powi(2) / expected)
            .sum();
        assert!(chi2 < 37.3, "chi2 = {chi2}, counts = {counts:?}");
    }
}
