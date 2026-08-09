//! Canonical Control-to-Relay desired state; complete snapshots make offline
//! verification and revocation ordering explicit.

use anyhow::{Context, Result};
use iroh_base::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};

const SIGNING_DOMAIN: &[u8] = b"agent-scale-relay-snapshot-v2\0";
pub const RELAY_PROTOCOL_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayMember {
    pub name: String,
    pub endpoint_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipSnapshot {
    pub protocol_version: u32,
    pub audience: String,
    pub version: u64,
    pub issued_at: i64,
    pub members: Vec<RelayMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSnapshot {
    pub snapshot: MembershipSnapshot,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStatus {
    pub audience: String,
    pub control_id: String,
    pub version: u64,
    pub members: usize,
}

impl MembershipSnapshot {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        anyhow::ensure!(
            self.protocol_version == RELAY_PROTOCOL_VERSION,
            "unsupported relay protocol version {}; expected {RELAY_PROTOCOL_VERSION}",
            self.protocol_version
        );
        let json = serde_json::to_vec(self).context("serialize membership snapshot")?;
        let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + json.len());
        bytes.extend_from_slice(SIGNING_DOMAIN);
        bytes.extend_from_slice(&json);
        Ok(bytes)
    }

    pub fn endpoint_ids(&self) -> Result<Vec<EndpointId>> {
        self.members
            .iter()
            .map(|member| {
                member
                    .endpoint_id
                    .parse()
                    .with_context(|| format!("invalid endpoint id for '{}'", member.name))
            })
            .collect()
    }
}

impl SignedSnapshot {
    pub fn sign(snapshot: MembershipSnapshot, key: &SecretKey) -> Result<Self> {
        let signature = key.sign(&snapshot.canonical_bytes()?);
        Ok(Self { snapshot, signature })
    }

    pub fn verify(&self, control_id: EndpointId) -> Result<()> {
        control_id
            .verify(&self.snapshot.canonical_bytes()?, &self.signature)
            .context("invalid Control signature")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(client: EndpointId) -> MembershipSnapshot {
        MembershipSnapshot {
            protocol_version: RELAY_PROTOCOL_VERSION,
            audience: "relay.example.test".into(),
            version: 1,
            issued_at: 42,
            members: vec![RelayMember {
                name: "client".into(),
                endpoint_id: client.to_string(),
            }],
        }
    }

    #[test]
    fn signed_snapshot_round_trip() {
        let key = SecretKey::generate();
        let signed = SignedSnapshot::sign(snapshot(key.public()), &key).unwrap();
        let json = serde_json::to_vec(&signed).unwrap();
        let decoded: SignedSnapshot = serde_json::from_slice(&json).unwrap();
        decoded.verify(key.public()).unwrap();
    }

    #[test]
    fn signature_is_bound_to_snapshot() {
        let key = SecretKey::generate();
        let mut signed = SignedSnapshot::sign(snapshot(key.public()), &key).unwrap();
        signed.snapshot.version += 1;
        assert!(signed.verify(key.public()).is_err());
    }

    #[test]
    fn unknown_protocol_version_cannot_be_signed() {
        let key = SecretKey::generate();
        let mut snapshot = snapshot(key.public());
        snapshot.protocol_version += 1;
        assert!(SignedSnapshot::sign(snapshot, &key).is_err());
    }
}
