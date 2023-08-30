use serde::{de::Visitor, Deserialize, Deserializer};
use webpki::DnsName;

#[derive(Clone)]
pub struct DomainName(pub(crate) webpki::DnsName);

struct DomainNameVisitor;

impl<'de> Visitor<'de> for DomainNameVisitor {
    type Value = DomainName;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expecting a domain name")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let name_ref =
            webpki::DnsNameRef::try_from_ascii_str(v).map_err(|e| serde::de::Error::custom(e))?;
        let name = DnsName::from(name_ref);
        Ok(DomainName(name))
    }
}

impl<'de> Deserialize<'de> for DomainName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(DomainNameVisitor)
    }
}
