//! Serde helpers that encode addresses as `"0x…"` strings so 64-bit values
//! survive JSON consumers that only have doubles.

use serde::{de::Error, Deserialize, Deserializer, Serializer};

pub fn parse(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u64::from_str_radix(t, 16).map_err(|e| format!("bad hex address {s:?}: {e}"))
}

pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("{v:#x}"))
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        S(String),
        N(u64),
    }
    match Either::deserialize(d)? {
        Either::S(s) => parse(&s).map_err(D::Error::custom),
        Either::N(n) => Ok(n),
    }
}

pub mod opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => super::serialize(v, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        #[derive(Deserialize)]
        struct W(#[serde(with = "super")] u64);
        Ok(Option::<W>::deserialize(d)?.map(|w| w.0))
    }
}

pub mod pair {
    use serde::{ser::SerializeTuple, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &(u64, u64), s: S) -> Result<S::Ok, S::Error> {
        let mut t = s.serialize_tuple(2)?;
        t.serialize_element(&format!("{:#x}", v.0))?;
        t.serialize_element(&format!("{:#x}", v.1))?;
        t.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<(u64, u64), D::Error> {
        #[derive(Deserialize)]
        struct W(#[serde(with = "super")] u64, #[serde(with = "super")] u64);
        let w = W::deserialize(d)?;
        Ok((w.0, w.1))
    }
}

pub mod pairs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct W(#[serde(with = "super::pair")] (u64, u64));

    pub fn serialize<S: Serializer>(v: &[(u64, u64)], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(|p| W(*p)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(u64, u64)>, D::Error> {
        Ok(Vec::<W>::deserialize(d)?.into_iter().map(|w| w.0).collect())
    }
}
