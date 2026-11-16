//! Time-based one-time passwords (RFC 6238, built on RFC 4226 HOTP).

use std::fmt;

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// HMAC hash used by the TOTP generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 (the default almost everywhere).
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

/// A TOTP generator. The shared secret is zeroized on drop.
pub struct Totp {
    secret: SecretBox<Vec<u8>>,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
}

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

impl Totp {
    /// Build from raw secret bytes.
    pub fn new(
        secret: Vec<u8>,
        algorithm: TotpAlgorithm,
        digits: u32,
        period: u64,
    ) -> Result<Self> {
        if secret.is_empty() {
            return Err(Error::InvalidTotp("empty secret"));
        }
        if !(6..=8).contains(&digits) {
            return Err(Error::InvalidTotp("digits must be 6, 7 or 8"));
        }
        if !(1..=3600).contains(&period) {
            return Err(Error::InvalidTotp("period must be 1..=3600 seconds"));
        }
        Ok(Self {
            secret: SecretBox::new(Box::new(secret)),
            algorithm,
            digits,
            period,
        })
    }

    /// Parse a base32 secret (spaces, dashes, lower case and `=` padding are
    /// tolerated) with the common defaults: SHA-1, 6 digits, 30 s.
    pub fn from_base32(s: &str) -> Result<Self> {
        Self::new(decode_base32(s)?, TotpAlgorithm::Sha1, 6, 30)
    }

    /// Parse an `otpauth://totp/...?secret=...` URI.
    pub fn from_uri(uri: &str) -> Result<Self> {
        let rest = uri
            .strip_prefix("otpauth://")
            .ok_or(Error::InvalidTotp("not an otpauth:// URI"))?;
        let (kind, rest) = rest
            .split_once('/')
            .ok_or(Error::InvalidTotp("missing type"))?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(Error::InvalidTotp("only totp URIs are supported"));
        }
        let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");

        let mut secret = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = Zeroizing::new(percent_decode(v)?);
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(decode_base32(&v)?),
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        _ => return Err(Error::InvalidTotp("unknown algorithm")),
                    }
                }
                "digits" => digits = v.parse().map_err(|_| Error::InvalidTotp("bad digits"))?,
                "period" => period = v.parse().map_err(|_| Error::InvalidTotp("bad period"))?,
                _ => {} // issuer, label params etc. are irrelevant for code generation
            }
        }
        let secret = secret.ok_or(Error::InvalidTotp("missing secret"))?;
        Self::new(secret, algorithm, digits, period)
    }

    /// Accept either an `otpauth://` URI or a bare base32 secret.
    pub fn parse(s: &str) -> Result<Self> {
        let t = s.trim();
        if t.len() >= 10 && t[..10].eq_ignore_ascii_case("otpauth://") {
            Self::from_uri(t)
        } else {
            Self::from_base32(t)
        }
    }

    /// The code valid at `unix_time` (seconds since the epoch).
    pub fn code_at(&self, unix_time: u64) -> SecretString {
        let counter = unix_time / self.period;
        let value = match self.algorithm {
            TotpAlgorithm::Sha1 => hotp::<Hmac<sha1::Sha1>>(self.secret.expose_secret(), counter),
            TotpAlgorithm::Sha256 => {
                hotp::<Hmac<sha2::Sha256>>(self.secret.expose_secret(), counter)
            }
            TotpAlgorithm::Sha512 => {
                hotp::<Hmac<sha2::Sha512>>(self.secret.expose_secret(), counter)
            }
        };
        let code = value % 10u32.pow(self.digits);
        SecretString::from(format!("{code:0width$}", width = self.digits as usize))
    }

    /// Seconds until the current code expires (1..=period).
    pub fn seconds_remaining(&self, unix_time: u64) -> u64 {
        self.period - unix_time % self.period
    }

    /// Code period in seconds.
    pub fn period(&self) -> u64 {
        self.period
    }
}

/// RFC 4226 HOTP with dynamic truncation; returns the 31-bit value.
fn hotp<M: Mac + hmac::digest::KeyInit>(key: &[u8], counter: u64) -> u32 {
    let mut mac = <M as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    let digest = Zeroizing::new(mac.finalize().into_bytes().to_vec());
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ])
}

fn decode_base32(s: &str) -> Result<Vec<u8>> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        s.chars()
            .filter(|c| !matches!(c, ' ' | '-' | '=' | '\t'))
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );
    BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| Error::InvalidTotp("secret is not valid base32"))
}

fn percent_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or(Error::InvalidTotp("bad percent-encoding"))?;
                out.push(hex);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidTotp("bad percent-encoding"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED20: &[u8] = b"12345678901234567890";
    const SEED32: &[u8] = b"12345678901234567890123456789012";
    const SEED64: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    /// RFC 6238 Appendix B: (time, SHA1, SHA256, SHA512), 8 digits, 30 s.
    const VECTORS: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn rfc6238_appendix_b() {
        let t1 = Totp::new(SEED20.to_vec(), TotpAlgorithm::Sha1, 8, 30).unwrap();
        let t256 = Totp::new(SEED32.to_vec(), TotpAlgorithm::Sha256, 8, 30).unwrap();
        let t512 = Totp::new(SEED64.to_vec(), TotpAlgorithm::Sha512, 8, 30).unwrap();
        for (t, s1, s256, s512) in VECTORS {
            assert_eq!(t1.code_at(t).expose_secret(), s1, "sha1 @ {t}");
            assert_eq!(t256.code_at(t).expose_secret(), s256, "sha256 @ {t}");
            assert_eq!(t512.code_at(t).expose_secret(), s512, "sha512 @ {t}");
        }
    }

    /// RFC 4226 Appendix D HOTP values for counters 0..=9.
    #[test]
    fn rfc4226_hotp_vectors() {
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (c, e) in expected.into_iter().enumerate() {
            assert_eq!(hotp::<Hmac<sha1::Sha1>>(SEED20, c as u64) % 1_000_000, e);
        }
    }

    #[test]
    fn base32_parsing_is_forgiving() {
        // "12345678901234567890" in base32
        let canonical = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let messy = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        let a = Totp::from_base32(canonical).unwrap();
        let b = Totp::parse(messy).unwrap();
        assert_eq!(a.code_at(59).expose_secret(), b.code_at(59).expose_secret());
        assert_eq!(a.code_at(59).expose_secret(), "287082"); // 6-digit tail of 94287082
        assert!(Totp::from_base32("not base32!!").is_err());
        assert!(Totp::from_base32("").is_err());
    }

    #[test]
    fn otpauth_uri() {
        let uri = "otpauth://totp/ACME%20Co:john@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
                   &issuer=ACME%20Co&algorithm=SHA1&digits=8&period=30";
        let t = Totp::parse(uri).unwrap();
        assert_eq!(t.code_at(59).expose_secret(), "94287082");
        assert_eq!(t.period(), 30);

        let t =
            Totp::from_uri("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=60")
                .unwrap();
        assert_eq!(t.period(), 60);
        assert_eq!(
            t.code_at(119).expose_secret(),
            t.code_at(60).expose_secret()
        );

        for bad in [
            "otpauth://hotp/x?secret=GEZDGNBV&counter=1",
            "otpauth://totp/x?issuer=nope",
            "otpauth://totp/x?secret=GEZDGNBV&digits=9",
            "otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5",
            "otpauth://totp/x?secret=GEZDGNBV&period=0",
            "otpauth://totp/x?secret=%ZZ",
            "https://example.com",
        ] {
            assert!(Totp::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn countdown() {
        let t = Totp::from_base32("GEZDGNBV").unwrap();
        assert_eq!(t.seconds_remaining(0), 30);
        assert_eq!(t.seconds_remaining(29), 1);
        assert_eq!(t.seconds_remaining(30), 30);
        // code changes exactly at the period boundary
        assert_eq!(t.code_at(0).expose_secret(), t.code_at(29).expose_secret());
        assert_ne!(t.code_at(29).expose_secret(), t.code_at(30).expose_secret());
    }

    #[test]
    fn codes_are_zero_padded() {
        // RFC vector 1111111109 for SHA1 starts with a 0
        let t = Totp::new(SEED20.to_vec(), TotpAlgorithm::Sha1, 8, 30).unwrap();
        assert_eq!(t.code_at(1111111109).expose_secret().len(), 8);
    }

    #[test]
    fn debug_hides_secret() {
        let t = Totp::new(b"supersecret".to_vec(), TotpAlgorithm::Sha1, 6, 30).unwrap();
        let d = format!("{t:?}");
        assert!(!d.contains("115") && !d.contains("supersecret"), "{d}");
    }
}
