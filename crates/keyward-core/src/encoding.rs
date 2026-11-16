//! Serde helpers: base64 for binary fields and secret-aware string fields.

/// Base64 (standard alphabet, padded) for `Vec<u8>` / `&[u8]`.
pub(crate) mod b64 {
    use data_encoding::BASE64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        BASE64
            .decode(s.as_bytes())
            .map_err(|_| serde::de::Error::custom("invalid base64"))
    }
}

/// Base64 for fixed-size arrays; rejects input of the wrong length.
pub(crate) mod b64_array {
    use data_encoding::BASE64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = BASE64
            .decode(s.as_bytes())
            .map_err(|_| serde::de::Error::custom("invalid base64"))?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

/// `SecretString` as a plain JSON string (only ever inside encrypted payloads).
pub(crate) mod secret_string {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &SecretString, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(v.expose_secret())
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
        String::deserialize(d).map(SecretString::from)
    }
}

/// `Option<SecretString>`.
pub(crate) mod opt_secret_string {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        v: &Option<SecretString>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_some(v.expose_secret()),
            None => s.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<SecretString>, D::Error> {
        Option::<String>::deserialize(d).map(|o| o.map(SecretString::from))
    }
}

/// Serialize to JSON in a buffer that is allocated once at its exact final
/// size, so no partially filled plaintext buffers are freed un-zeroized by
/// `Vec` growth. Costs a second (counting) serialization pass.
pub(crate) fn to_json_zeroizing<T: serde::Serialize>(
    value: &T,
) -> Result<zeroize::Zeroizing<Vec<u8>>, serde_json::Error> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut c = Counter(0);
    serde_json::to_writer(&mut c, value)?;
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(c.0));
    serde_json::to_writer(&mut *out, value)?;
    debug_assert_eq!(out.len(), out.capacity());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Fixed {
        #[serde(with = "super::b64_array")]
        n: [u8; 4],
        #[serde(with = "super::b64")]
        v: Vec<u8>,
    }

    #[test]
    fn base64_round_trip() {
        let x = Fixed {
            n: [1, 2, 3, 4],
            v: vec![9; 7],
        };
        let j = serde_json::to_string(&x).unwrap();
        assert_eq!(serde_json::from_str::<Fixed>(&j).unwrap(), x);
    }

    #[test]
    fn exact_size_json_matches_serde_json() {
        let x = Fixed {
            n: [0; 4],
            v: (0..200).collect(),
        };
        let a = super::to_json_zeroizing(&x).unwrap();
        assert_eq!(a.as_slice(), serde_json::to_vec(&x).unwrap().as_slice());
        assert_eq!(a.len(), a.capacity());
    }

    #[test]
    fn fixed_array_rejects_wrong_length() {
        let j = r#"{"n":"AQID","v":""}"#; // 3 bytes, expected 4
        assert!(serde_json::from_str::<Fixed>(j).is_err());
    }
}
