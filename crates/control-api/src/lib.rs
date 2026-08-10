//! One canonical serialization surface prevents participants from signing
//! subtly different representations of the same Control message.

mod provisioner;

pub use provisioner::{
    ManagedClientInfo, ManagedEdgeInfo, PROVISIONER_AUTH_SCHEME, ProvisionerAction, ProvisionerHttpRequest,
    ProvisionerRequest, ProvisionerResponse, ProvisionerTopology, action_hash, provisioner_authorization,
    provisioner_signing_bytes, verify_provisioner_authorization,
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh_base::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

const INVITE_DOMAIN: &[u8] = b"agent-scale-control-invite-v5\0";
const CLAIM_DOMAIN: &[u8] = b"agent-scale-control-claim-v5\0";
const EDGE_INVITE_REQUEST_DOMAIN: &[u8] = b"agent-scale-control-edge-invite-request-v5\0";
const EDGE_REMOVE_REQUEST_DOMAIN: &[u8] = b"agent-scale-control-edge-remove-request-v5\0";
const STATUS_REQUEST_DOMAIN: &[u8] = b"agent-scale-control-status-request-v5\0";
const WATCH_DOMAIN: &[u8] = b"agent-scale-control-watch-v5\0";
const MAP_DOMAIN: &[u8] = b"agent-scale-control-map-v5\0";
pub const CONTROL_PROTOCOL_VERSION: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InviteKind {
    Client,
    Edge { owner_id: String },
    Relay { url: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub protocol_version: u32,
    pub audience: String,
    pub control_url: String,
    pub control_id: String,
    pub invite_id: String,
    pub name: String,
    pub kind: InviteKind,
    pub secret_hash: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinToken {
    pub invite: Invite,
    pub secret: String,
    pub signature: Signature,
}

impl JoinToken {
    pub fn new(invite: Invite, secret: String, key: &SecretKey) -> Result<Self> {
        let signature = key.sign(&domain_bytes(INVITE_DOMAIN, &invite)?);
        Ok(Self {
            invite,
            secret,
            signature,
        })
    }

    pub fn verify(&self) -> Result<EndpointId> {
        ensure_protocol_version(self.invite.protocol_version)?;
        let id: EndpointId = self.invite.control_id.parse().context("invalid control id")?;
        id.verify(&domain_bytes(INVITE_DOMAIN, &self.invite)?, &self.signature)
            .context("invalid invite signature")?;
        anyhow::ensure!(
            hash_secret(&self.secret) == self.invite.secret_hash,
            "invalid invite secret"
        );
        Ok(id)
    }

    pub fn encode(&self) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?))
    }

    pub fn decode(value: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(value).context("invalid join token encoding")?;
        serde_json::from_slice(&bytes).context("invalid join token")
    }

    pub fn join_url(&self) -> Result<String> {
        Ok(format!(
            "{}/join#{}",
            self.invite.control_url.trim_end_matches('/'),
            self.encode()?
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub protocol_version: u32,
    pub invite_id: String,
    pub endpoint_id: String,
    pub issued_at: i64,
    pub nonce: String,
    /// Public UDP port advertised by an enrolling managed Relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_qad_port: Option<u16>,
    /// DER PKCS#10 request for a managed Relay's QAD certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_tls_csr: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub token: JoinToken,
    pub claim: Claim,
    pub signature: Signature,
}

impl ClaimRequest {
    pub fn sign(token: JoinToken, key: &SecretKey, issued_at: i64, nonce: String) -> Result<Self> {
        Self::sign_with_relay_qad(token, key, issued_at, nonce, None, None)
    }

    pub fn sign_with_relay_qad(
        token: JoinToken,
        key: &SecretKey,
        issued_at: i64,
        nonce: String,
        relay_qad_port: Option<u16>,
        relay_tls_csr: Option<Vec<u8>>,
    ) -> Result<Self> {
        let claim = Claim {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            invite_id: token.invite.invite_id.clone(),
            endpoint_id: key.public().to_string(),
            issued_at,
            nonce,
            relay_qad_port,
            relay_tls_csr,
        };
        let signature = key.sign(&domain_bytes(CLAIM_DOMAIN, &claim)?);
        Ok(Self {
            token,
            claim,
            signature,
        })
    }

    pub fn verify(&self) -> Result<EndpointId> {
        ensure_protocol_version(self.claim.protocol_version)?;
        anyhow::ensure!(
            self.claim.invite_id == self.token.invite.invite_id,
            "invite id mismatch"
        );
        let id: EndpointId = self.claim.endpoint_id.parse().context("invalid endpoint id")?;
        id.verify(&domain_bytes(CLAIM_DOMAIN, &self.claim)?, &self.signature)
            .context("invalid claim signature")?;
        Ok(id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeInviteRequest {
    pub protocol_version: u32,
    pub client_id: String,
    pub audience: String,
    pub request_id: String,
    pub issued_at: i64,
    pub name: String,
    pub ttl_secs: u64,
    pub signature: Signature,
}

impl EdgeInviteRequest {
    pub fn sign(
        key: &SecretKey,
        audience: String,
        request_id: String,
        issued_at: i64,
        name: String,
        ttl_secs: u64,
    ) -> Result<Self> {
        let mut request = Self {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            client_id: key.public().to_string(),
            audience,
            request_id,
            issued_at,
            name,
            ttl_secs,
            signature: key.sign(b"placeholder"),
        };
        request.signature = key.sign(&request.signing_bytes()?);
        Ok(request)
    }

    pub fn verify(&self) -> Result<EndpointId> {
        ensure_protocol_version(self.protocol_version)?;
        let id: EndpointId = self.client_id.parse().context("invalid client id")?;
        id.verify(&self.signing_bytes()?, &self.signature)
            .context("invalid edge invitation request signature")?;
        Ok(id)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        domain_bytes(
            EDGE_INVITE_REQUEST_DOMAIN,
            &(
                self.protocol_version,
                &self.client_id,
                &self.audience,
                &self.request_id,
                self.issued_at,
                &self.name,
                self.ttl_secs,
            ),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRemoveRequest {
    pub protocol_version: u32,
    pub client_id: String,
    pub audience: String,
    pub nonce: String,
    pub issued_at: i64,
    pub name: String,
    pub endpoint_id: String,
    pub signature: Signature,
}

impl EdgeRemoveRequest {
    pub fn sign(
        key: &SecretKey,
        audience: String,
        nonce: String,
        issued_at: i64,
        name: String,
        endpoint_id: String,
    ) -> Result<Self> {
        endpoint_id.parse::<EndpointId>().context("invalid edge endpoint id")?;
        let mut request = Self {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            client_id: key.public().to_string(),
            audience,
            nonce,
            issued_at,
            name,
            endpoint_id,
            signature: key.sign(b"placeholder"),
        };
        request.signature = key.sign(&request.signing_bytes()?);
        Ok(request)
    }

    pub fn verify(&self) -> Result<EndpointId> {
        ensure_protocol_version(self.protocol_version)?;
        self.endpoint_id
            .parse::<EndpointId>()
            .context("invalid edge endpoint id")?;
        let id: EndpointId = self.client_id.parse().context("invalid client id")?;
        id.verify(&self.signing_bytes()?, &self.signature)
            .context("invalid edge removal request signature")?;
        Ok(id)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        domain_bytes(
            EDGE_REMOVE_REQUEST_DOMAIN,
            &(
                self.protocol_version,
                &self.client_id,
                &self.audience,
                &self.nonce,
                self.issued_at,
                &self.name,
                &self.endpoint_id,
            ),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRequest {
    pub protocol_version: u32,
    pub client_id: String,
    pub audience: String,
    pub issued_at: i64,
    pub nonce: String,
    pub signature: Signature,
}

impl StatusRequest {
    pub fn sign(key: &SecretKey, audience: String, issued_at: i64, nonce: String) -> Result<Self> {
        let mut request = Self {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            client_id: key.public().to_string(),
            audience,
            issued_at,
            nonce,
            signature: key.sign(b"placeholder"),
        };
        request.signature = key.sign(&request.signing_bytes()?);
        Ok(request)
    }

    pub fn verify(&self) -> Result<EndpointId> {
        ensure_protocol_version(self.protocol_version)?;
        let id: EndpointId = self.client_id.parse().context("invalid client id")?;
        id.verify(&self.signing_bytes()?, &self.signature)
            .context("invalid status request signature")?;
        Ok(id)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        domain_bytes(
            STATUS_REQUEST_DOMAIN,
            &(
                self.protocol_version,
                &self.client_id,
                &self.audience,
                self.issued_at,
                &self.nonce,
            ),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchRequest {
    pub protocol_version: u32,
    pub endpoint_id: String,
    pub known_revision: u64,
    pub issued_at: i64,
    pub nonce: String,
    /// Current public QAD port, reported only by a managed Relay watcher.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_qad_port: Option<u16>,
    pub signature: Signature,
}

impl WatchRequest {
    pub fn sign(key: &SecretKey, known_revision: u64, issued_at: i64, nonce: String) -> Result<Self> {
        let mut request = Self {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            endpoint_id: key.public().to_string(),
            known_revision,
            issued_at,
            nonce,
            relay_qad_port: None,
            signature: key.sign(b"placeholder"),
        };
        request.signature = key.sign(&request.signing_bytes()?);
        Ok(request)
    }

    pub fn sign_relay(
        key: &SecretKey,
        known_revision: u64,
        issued_at: i64,
        nonce: String,
        relay_qad_port: Option<u16>,
    ) -> Result<Self> {
        let mut request = Self::sign(key, known_revision, issued_at, nonce)?;
        request.relay_qad_port = relay_qad_port;
        request.signature = key.sign(&request.signing_bytes()?);
        Ok(request)
    }

    pub fn verify(&self) -> Result<EndpointId> {
        ensure_protocol_version(self.protocol_version)?;
        let id: EndpointId = self.endpoint_id.parse().context("invalid endpoint id")?;
        id.verify(&self.signing_bytes()?, &self.signature)
            .context("invalid watch signature")?;
        Ok(id)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        domain_bytes(
            WATCH_DOMAIN,
            &(
                self.protocol_version,
                &self.endpoint_id,
                self.known_revision,
                self.issued_at,
                &self.nonce,
                self.relay_qad_port,
            ),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayInfo {
    pub name: String,
    pub url: String,
    pub qad_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeInfo {
    pub name: String,
    pub endpoint_id: String,
    pub owner_id: String,
    pub owner_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub endpoint_id: String,
    pub edges: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayNodeInfo {
    pub name: String,
    pub endpoint_id: String,
    pub url: String,
    pub qad_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteInfo {
    pub invite_id: String,
    pub name: String,
    pub kind: InviteKind,
    pub expires_at: i64,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overview {
    pub revision: u64,
    pub clients: Vec<ClientInfo>,
    pub edges: Vec<EdgeInfo>,
    pub relays: Vec<RelayNodeInfo>,
    pub invites: Vec<InviteInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMap {
    pub protocol_version: u32,
    pub audience: String,
    pub control_url: String,
    pub control_id: String,
    pub revision: u64,
    pub issued_at: i64,
    pub recipient_id: String,
    pub relays: Vec<RelayInfo>,
    /// Relays authenticate to Control directly, so only Client and Edge maps carry this credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_credential: Option<String>,
    /// DER-encoded private CA certificate used only for managed Relay TLS.
    pub relay_ca_der: Vec<u8>,
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    #[serde(default)]
    pub edges: Vec<EdgeInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedNodeMap {
    pub map: NodeMap,
    pub signature: Signature,
}

impl SignedNodeMap {
    pub fn sign(map: NodeMap, key: &SecretKey) -> Result<Self> {
        let signature = key.sign(&domain_bytes(MAP_DOMAIN, &map)?);
        Ok(Self { map, signature })
    }

    pub fn verify(&self, control_id: EndpointId, recipient: EndpointId) -> Result<()> {
        ensure_protocol_version(self.map.protocol_version)?;
        anyhow::ensure!(self.map.control_id == control_id.to_string(), "control id mismatch");
        anyhow::ensure!(self.map.recipient_id == recipient.to_string(), "map recipient mismatch");
        control_id
            .verify(&domain_bytes(MAP_DOMAIN, &self.map)?, &self.signature)
            .context("invalid node map signature")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlStatus {
    pub audience: String,
    pub control_url: String,
    pub control_id: String,
    pub revision: u64,
    pub clients: usize,
    pub edges: usize,
    pub relays: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinResult {
    pub name: String,
    pub kind: InviteKind,
    pub map: SignedNodeMap,
    /// DER leaf certificate returned only while enrolling a managed Relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_tls_certificate_der: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteResult {
    pub invite_id: String,
    pub join_url: String,
    pub expires_at: i64,
}

pub fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"agent-scale-invite-secret-v2\0");
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

pub(crate) fn ensure_protocol_version(version: u32) -> Result<()> {
    anyhow::ensure!(
        version == CONTROL_PROTOCOL_VERSION,
        "unsupported control protocol version {version}; expected {CONTROL_PROTOCOL_VERSION}"
    );
    Ok(())
}

pub(crate) fn domain_bytes<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(value).context("serialize signed payload")?;
    let mut bytes = Vec::with_capacity(domain.len() + encoded.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

pub fn decode_json_fragment<T: DeserializeOwned>(value: &str) -> Result<T> {
    let bytes = URL_SAFE_NO_PAD.decode(value).context("invalid base64url")?;
    serde_json::from_slice(&bytes).context("invalid encoded JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_and_claim_are_bound_to_keys() {
        let control = SecretKey::generate();
        let node = SecretKey::generate();
        let secret = "a".repeat(43);
        let invite = Invite {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            audience: "prod".into(),
            control_url: "https://control.example".into(),
            control_id: control.public().to_string(),
            invite_id: "invite".into(),
            name: "dev".into(),
            kind: InviteKind::Client,
            secret_hash: hash_secret(&secret),
            expires_at: 100,
        };
        let token = JoinToken::new(invite, secret, &control).unwrap();
        assert_eq!(token.verify().unwrap(), control.public());
        let request = ClaimRequest::sign(token, &node, 50, "nonce".into()).unwrap();
        assert_eq!(request.verify().unwrap(), node.public());
    }

    #[test]
    fn unknown_protocol_version_is_rejected_even_when_signed() {
        let control = SecretKey::generate();
        let secret = "a".repeat(43);
        let invite = Invite {
            protocol_version: CONTROL_PROTOCOL_VERSION + 1,
            audience: "prod".into(),
            control_url: "https://control.example".into(),
            control_id: control.public().to_string(),
            invite_id: "invite".into(),
            name: "dev".into(),
            kind: InviteKind::Client,
            secret_hash: hash_secret(&secret),
            expires_at: 100,
        };
        let token = JoinToken::new(invite, secret, &control).unwrap();
        assert!(
            token
                .verify()
                .unwrap_err()
                .to_string()
                .contains("unsupported control protocol")
        );
    }

    #[test]
    fn edge_invite_request_is_bound_to_client_and_payload() {
        let client = SecretKey::generate();
        let request =
            EdgeInviteRequest::sign(&client, "prod".into(), "request".into(), 50, "win-box".into(), 900).unwrap();
        assert_eq!(request.verify().unwrap(), client.public());

        let mut tampered = request;
        tampered.name = "other-box".into();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn edge_remove_request_is_bound_to_the_current_edge_identity() {
        let client = SecretKey::generate();
        let edge = SecretKey::generate();
        let request = EdgeRemoveRequest::sign(
            &client,
            "prod".into(),
            "nonce".into(),
            50,
            "win-box".into(),
            edge.public().to_string(),
        )
        .unwrap();
        assert_eq!(request.verify().unwrap(), client.public());

        let mut tampered = request;
        tampered.endpoint_id = SecretKey::generate().public().to_string();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn status_request_is_bound_to_client_and_audience() {
        let client = SecretKey::generate();
        let request = StatusRequest::sign(&client, "prod".into(), 50, "nonce".into()).unwrap();
        assert_eq!(request.verify().unwrap(), client.public());

        let mut tampered = request;
        tampered.audience = "other".into();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn relay_watch_binds_the_reported_qad_port_to_its_signature() {
        let relay = SecretKey::generate();
        let request = WatchRequest::sign_relay(&relay, 4, 50, "nonce".into(), Some(4433)).unwrap();
        assert_eq!(request.verify().unwrap(), relay.public());

        let mut tampered = request;
        tampered.relay_qad_port = Some(7842);
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn node_map_is_recipient_bound() {
        let control = SecretKey::generate();
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        let signed = SignedNodeMap::sign(
            NodeMap {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                audience: "prod".into(),
                control_url: "https://control.example".into(),
                control_id: control.public().to_string(),
                revision: 1,
                issued_at: 1,
                recipient_id: a.public().to_string(),
                relays: vec![],
                relay_credential: None,
                relay_ca_der: vec![1, 2, 3],
                allowed_clients: vec![],
                edges: vec![],
            },
            &control,
        )
        .unwrap();
        signed.verify(control.public(), a.public()).unwrap();
        assert!(signed.verify(control.public(), b.public()).is_err());
    }
}
