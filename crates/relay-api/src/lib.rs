//! Signed Relay admission credentials and Control-managed revocation state.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh_base::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};

const CREDENTIAL_DOMAIN: &[u8] = b"agent-scale-relay-credential-v3\0";
const REVOCATION_DOMAIN: &[u8] = b"agent-scale-relay-revocations-v3\0";
pub const RELAY_PROTOCOL_VERSION: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelaySubjectKind {
    Client,
    Edge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayCredential {
    pub protocol_version: u32,
    pub audience: String,
    pub control_id: String,
    pub endpoint_id: String,
    pub kind: RelaySubjectKind,
    pub generation: u64,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRelayCredential {
    pub credential: RelayCredential,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub endpoint_id: String,
    pub revoked_through_generation: u64,
    pub expires_at: i64,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationUpdate {
    pub protocol_version: u32,
    pub audience: String,
    pub version: u64,
    pub issued_at: i64,
    pub revocations: Vec<Revocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRevocationUpdate {
    pub update: RevocationUpdate,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStatus {
    pub audience: String,
    pub control_id: String,
    pub version: u64,
    pub revocations: usize,
}

impl RelayCredential {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(CREDENTIAL_DOMAIN, self)
    }

    pub fn endpoint_id(&self) -> Result<EndpointId> {
        self.endpoint_id.parse().context("invalid credential endpoint id")
    }
}

impl SignedRelayCredential {
    pub fn sign(credential: RelayCredential, key: &SecretKey) -> Result<Self> {
        credential.validate()?;
        let signature = key.sign(&credential.canonical_bytes()?);
        Ok(Self { credential, signature })
    }

    pub fn verify(&self, control_id: EndpointId) -> Result<()> {
        anyhow::ensure!(
            self.credential.control_id == control_id.to_string(),
            "control id mismatch"
        );
        control_id
            .verify(&self.credential.canonical_bytes()?, &self.signature)
            .context("invalid Control signature")
    }

    pub fn encode(&self) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).context("serialize Relay credential")?))
    }

    pub fn decode(value: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .context("invalid Relay credential encoding")?;
        serde_json::from_slice(&bytes).context("invalid Relay credential")
    }
}

impl RevocationUpdate {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(REVOCATION_DOMAIN, self)
    }

    pub fn entries(&self) -> Result<Vec<(EndpointId, u64)>> {
        self.revocations
            .iter()
            .map(|revocation| {
                Ok((
                    revocation
                        .endpoint_id
                        .parse()
                        .with_context(|| format!("invalid revoked endpoint id '{}'", revocation.endpoint_id))?,
                    revocation.revoked_through_generation,
                ))
            })
            .collect()
    }
}

impl SignedRevocationUpdate {
    pub fn sign(update: RevocationUpdate, key: &SecretKey) -> Result<Self> {
        update.validate()?;
        let signature = key.sign(&update.canonical_bytes()?);
        Ok(Self { update, signature })
    }

    pub fn verify(&self, control_id: EndpointId) -> Result<()> {
        control_id
            .verify(&self.update.canonical_bytes()?, &self.signature)
            .context("invalid Control signature")
    }
}

fn canonical_bytes<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(value).context("serialize signed Relay payload")?;
    let mut bytes = Vec::with_capacity(domain.len() + json.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&json);
    Ok(bytes)
}

fn ensure_protocol_version(version: u32) -> Result<()> {
    anyhow::ensure!(
        version == RELAY_PROTOCOL_VERSION,
        "unsupported Relay protocol version {version}; expected {RELAY_PROTOCOL_VERSION}"
    );
    Ok(())
}

impl RelayCredential {
    pub fn validate(&self) -> Result<()> {
        ensure_protocol_version(self.protocol_version)?;
        anyhow::ensure!(!self.audience.is_empty(), "credential audience is empty");
        anyhow::ensure!(self.generation > 0, "credential generation must be positive");
        anyhow::ensure!(
            self.expires_at > self.issued_at,
            "credential expiry must follow issuance"
        );
        self.endpoint_id()?;
        self.control_id
            .parse::<EndpointId>()
            .context("invalid credential control id")?;
        Ok(())
    }
}

impl RevocationUpdate {
    pub fn validate(&self) -> Result<()> {
        ensure_protocol_version(self.protocol_version)?;
        anyhow::ensure!(!self.audience.is_empty(), "revocation audience is empty");
        for revocation in &self.revocations {
            anyhow::ensure!(
                revocation.revoked_through_generation > 0,
                "revoked generation must be positive"
            );
            anyhow::ensure!(
                revocation.revision > 0 && revocation.revision <= self.version,
                "revocation revision is outside the signed update range"
            );
        }
        self.entries()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(control: EndpointId, endpoint: EndpointId) -> RelayCredential {
        RelayCredential {
            protocol_version: RELAY_PROTOCOL_VERSION,
            audience: "prod".into(),
            control_id: control.to_string(),
            endpoint_id: endpoint.to_string(),
            kind: RelaySubjectKind::Edge,
            generation: 7,
            issued_at: 40,
            expires_at: 80,
        }
    }

    #[test]
    fn credential_token_round_trip_is_endpoint_bound() {
        let control = SecretKey::generate();
        let endpoint = SecretKey::generate();
        let signed = SignedRelayCredential::sign(credential(control.public(), endpoint.public()), &control).unwrap();
        let decoded = SignedRelayCredential::decode(&signed.encode().unwrap()).unwrap();
        decoded.verify(control.public()).unwrap();
        decoded.credential.validate().unwrap();
        assert_eq!(decoded.credential.endpoint_id().unwrap(), endpoint.public());
    }

    #[test]
    fn credential_signature_covers_generation() {
        let control = SecretKey::generate();
        let endpoint = SecretKey::generate();
        let mut signed =
            SignedRelayCredential::sign(credential(control.public(), endpoint.public()), &control).unwrap();
        signed.credential.generation += 1;
        assert!(signed.verify(control.public()).is_err());
    }

    #[test]
    fn revocation_update_round_trip() {
        let control = SecretKey::generate();
        let endpoint = SecretKey::generate();
        let update = RevocationUpdate {
            protocol_version: RELAY_PROTOCOL_VERSION,
            audience: "prod".into(),
            version: 3,
            issued_at: 50,
            revocations: vec![Revocation {
                endpoint_id: endpoint.public().to_string(),
                revoked_through_generation: 2,
                expires_at: 90,
                revision: 3,
            }],
        };
        let signed = SignedRevocationUpdate::sign(update, &control).unwrap();
        signed.verify(control.public()).unwrap();
        signed.update.validate().unwrap();
    }
}
