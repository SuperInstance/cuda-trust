/*!
# I2I Message Types

Trust-aware message envelope for the iron-to-iron fleet protocol.

Every I2I message carries a trust attestation — a cryptographic record of the
sender's trust score, chain provenance, and hop history. This allows receiving
agents to make instant trust-based routing decisions without querying the
registry.
*/

use crate::{now, TrustScore, TrustRegistry};
use serde::{Deserialize, Serialize};
use std::fmt;

/// I2I message kinds in the fleet protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum I2IMessageKind {
    /// Point-to-point request.
    Request,
    /// Reply to a request.
    Response,
    /// Broadcast to all agents.
    Broadcast,
    /// Gossip — trust information sharing between agents.
    Gossip,
    /// Keep-alive heartbeat with trust piggyback.
    Heartbeat,
    /// Trust attestation — explicit trust score exchange.
    TrustAttestation,
}

/// A cryptographic trust signature from an agent along the message chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustSignature {
    /// Agent that signed.
    pub agent_id: String,
    /// Trust score of the sender at the time of signing.
    pub trust_at_time: f64,
    /// Confidence of the trust score.
    pub confidence_at_time: f64,
    /// Timestamp of the signature.
    pub timestamp: u64,
}

impl TrustSignature {
    pub fn new(agent_id: &str, trust: f64, confidence: f64) -> Self {
        TrustSignature {
            agent_id: agent_id.to_string(),
            trust_at_time: trust,
            confidence_at_time: confidence,
            timestamp: now(),
        }
    }
}

/// Trust attestation attached to every I2I message.
///
/// Records the sender's current trust level, accumulated chain trust
/// (product of trust scores along the relay chain), and all intermediate
/// signatures for auditability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustAttestation {
    /// Sender's trust score at send time.
    pub sender_trust_score: f64,
    /// Confidence in the sender's trust score.
    pub sender_confidence: f64,
    /// Accumulated trust along the relay chain (product).
    pub chain_trust: f64,
    /// Number of hops this message has taken.
    pub hops: u32,
    /// Trust context for this message.
    pub trust_context: String,
    /// Signatures from all agents that relayed this message.
    pub signatures: Vec<TrustSignature>,
    /// When this attestation was created.
    pub created_at: u64,
}

impl TrustAttestation {
    /// Create a fresh attestation from a trust score.
    pub fn new(trust_score: &TrustScore) -> Self {
        TrustAttestation {
            sender_trust_score: trust_score.value,
            sender_confidence: trust_score.confidence,
            chain_trust: trust_score.value,
            hops: 0,
            trust_context: trust_score.context.clone(),
            signatures: vec![],
            created_at: now(),
        }
    }

    /// Create attestation for a specific agent and context.
    pub fn for_agent(registry: &TrustRegistry, sender: &str, context: &str) -> Self {
        let trust = registry.trust_level(sender, sender, context);
        TrustAttestation {
            sender_trust_score: trust,
            sender_confidence: 0.1,
            chain_trust: trust,
            hops: 0,
            trust_context: context.to_string(),
            signatures: vec![],
            created_at: now(),
        }
    }

    /// Add a relay hop to the attestation.
    pub fn add_hop(&mut self, agent_id: &str, trust: f64, confidence: f64) {
        self.chain_trust *= trust;
        self.hops += 1;
        self.signatures.push(TrustSignature::new(agent_id, trust, confidence));
    }

    /// Minimum trust across all signatures.
    pub fn min_signature_trust(&self) -> f64 {
        self.signatures
            .iter()
            .map(|s| s.trust_at_time)
            .fold(f64::INFINITY, |a, b| a.min(b))
            .min(self.sender_trust_score)
    }

    /// Whether this attestation has expired.
    pub fn is_expired(&self, ttl_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.created_at) > ttl_ms
    }
}

/// Unique identifier for I2I messages.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        MessageId(format!("i2i-{}", ts))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The core I2I envelope — every fleet message is wrapped in this.
///
/// Contains the message metadata, payload, and trust attestation.
/// The payload is opaque bytes so the trust layer doesn't need to
/// know about the application-level message format.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct I2IEnvelope {
    /// Unique message identifier.
    pub id: MessageId,
    /// Sender agent ID.
    pub sender: String,
    /// Recipient agent ID (None for broadcasts).
    pub recipient: Option<String>,
    /// Message kind.
    pub kind: I2IMessageKind,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
    /// When the message was sent.
    pub timestamp: u64,
    /// Trust context for trust lookups.
    pub trust_context: String,
    /// Trust attestation.
    pub trust_attestation: TrustAttestation,
}

impl I2IEnvelope {
    /// Create a new I2I envelope with trust attestation.
    pub fn new(
        sender: &str,
        recipient: Option<&str>,
        kind: I2IMessageKind,
        payload: Vec<u8>,
        trust_attestation: TrustAttestation,
    ) -> Self {
        I2IEnvelope {
            id: MessageId::new(),
            sender: sender.to_string(),
            recipient: recipient.map(|r| r.to_string()),
            kind,
            payload,
            timestamp: now(),
            trust_context: trust_attestation.trust_context.clone(),
            trust_attestation,
        }
    }

    /// Create an envelope from a trust score.
    pub fn with_trust_score(
        sender: &str,
        recipient: Option<&str>,
        kind: I2IMessageKind,
        payload: Vec<u8>,
        trust_score: &TrustScore,
    ) -> Self {
        let attestation = TrustAttestation::new(trust_score);
        Self::new(sender, recipient, kind, payload, attestation)
    }

    /// Add a relay hop (for message forwarding).
    pub fn relay(&mut self, agent_id: &str, trust: f64, confidence: f64) {
        self.trust_attestation.add_hop(agent_id, trust, confidence);
    }

    /// Whether this message is a broadcast.
    pub fn is_broadcast(&self) -> bool {
        self.recipient.is_none() || self.kind == I2IMessageKind::Broadcast
    }

    /// Serialize the envelope to JSON bytes.
    pub fn to_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Deserialize an envelope from JSON bytes.
    pub fn from_json_bytes(data: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(data)
    }
}

/// A trust-aware wrapper around any serializable payload.
///
/// Generic type T is the application-level message type.
/// The wrapper adds trust attestation for I2I transport.
#[derive(Clone, Debug)]
pub struct TrustAwareMessage<T: Serialize + for<'de> Deserialize<'de>> {
    /// The application-level payload.
    pub inner: T,
    /// Trust attestation for this message.
    pub trust: TrustAttestation,
    /// Sender agent ID.
    pub sender: String,
    /// Recipient agent ID.
    pub recipient: Option<String>,
    /// Message timestamp.
    pub timestamp: u64,
}

// Manual serde implementations for TrustAwareMessage (needed for generic bounds)
impl<T: Serialize + for<'de> Deserialize<'de>> Serialize for TrustAwareMessage<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("TrustAwareMessage", 5)?;
        state.serialize_field("inner", &self.inner)?;
        state.serialize_field("trust", &self.trust)?;
        state.serialize_field("sender", &self.sender)?;
        state.serialize_field("recipient", &self.recipient)?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.end()
    }
}

impl<'de, T: Serialize + for<'de2> Deserialize<'de2>> Deserialize<'de> for TrustAwareMessage<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct TrustAwareMessageHelper<T> {
            inner: T,
            trust: TrustAttestation,
            sender: String,
            recipient: Option<String>,
            timestamp: u64,
        }
        let helper = TrustAwareMessageHelper::deserialize(deserializer)?;
        Ok(TrustAwareMessage {
            inner: helper.inner,
            trust: helper.trust,
            sender: helper.sender,
            recipient: helper.recipient,
            timestamp: helper.timestamp,
        })
    }
}

impl<T: Serialize + for<'de> Deserialize<'de>> TrustAwareMessage<T> {
    /// Wrap a payload with trust information.
    pub fn new(inner: T, sender: &str, recipient: Option<&str>, trust: TrustAttestation) -> Self {
        TrustAwareMessage {
            inner,
            trust,
            sender: sender.to_string(),
            recipient: recipient.map(|r| r.to_string()),
            timestamp: now(),
        }
    }

    /// Wrap with a trust score.
    pub fn with_score(inner: T, sender: &str, recipient: Option<&str>, score: &TrustScore) -> Self {
        Self::new(inner, sender, recipient, TrustAttestation::new(score))
    }

    /// Unwrap into the inner payload and attestation.
    pub fn into_parts(self) -> (T, TrustAttestation) {
        (self.inner, self.trust)
    }

    /// Serialize to JSON bytes.
    pub fn to_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Deserialize from JSON bytes.
    pub fn from_json_bytes(data: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(data)
    }
}

/// I2I protocol version header for wire compatibility.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct I2IProtocolHeader {
    pub version: u32,
    pub message_id: String,
    pub trust_enabled: bool,
}

impl I2IProtocolHeader {
    pub fn current(message_id: &str) -> Self {
        I2IProtocolHeader {
            version: 1,
            message_id: message_id.to_string(),
            trust_enabled: true,
        }
    }
}

impl Default for I2IProtocolHeader {
    fn default() -> Self {
        I2IProtocolHeader {
            version: 1,
            message_id: String::new(),
            trust_enabled: true,
        }
    }
}

/// Serialized trust score for wire transport.
///
/// A compact representation of a trust score suitable for
/// embedding in I2I messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireTrustScore {
    pub value: f64,
    pub confidence: f64,
    pub positive: u32,
    pub negative: u32,
    pub context: String,
    pub timestamp: u64,
}

impl WireTrustScore {
    /// Convert from a TrustScore.
    pub fn from_score(score: &TrustScore) -> Self {
        WireTrustScore {
            value: score.value,
            confidence: score.confidence,
            positive: score.positive_interactions,
            negative: score.negative_interactions,
            context: score.context.clone(),
            timestamp: score.last_interaction,
        }
    }

    /// Convert to a TrustScore.
    pub fn to_score(&self) -> TrustScore {
        TrustScore {
            value: self.value,
            confidence: self.confidence,
            positive_interactions: self.positive,
            negative_interactions: self.negative,
            last_interaction: self.timestamp,
            created: self.timestamp,
            context: self.context.clone(),
        }
    }

    /// Serialize to compact bytes.
    pub fn to_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_attestation_new() {
        let ts = TrustScore::new("nav");
        let att = TrustAttestation::new(&ts);
        assert_eq!(att.sender_trust_score, 0.5);
        assert_eq!(att.hops, 0);
        assert!(att.signatures.is_empty());
    }

    #[test]
    fn test_trust_attestation_add_hop() {
        let ts = TrustScore::new("nav");
        let mut att = TrustAttestation::new(&ts);
        att.add_hop("relay1", 0.8, 0.7);
        assert_eq!(att.hops, 1);
        assert!((att.chain_trust - 0.4).abs() < 0.01); // 0.5 * 0.8
        assert_eq!(att.signatures.len(), 1);
    }

    #[test]
    fn test_trust_attestation_min_signature_trust() {
        let ts = TrustScore::new("nav");
        let mut att = TrustAttestation::new(&ts);
        att.add_hop("a", 0.9, 0.8);
        att.add_hop("b", 0.3, 0.5);
        att.add_hop("c", 0.7, 0.6);
        assert!((att.min_signature_trust() - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_trust_attestation_no_signatures() {
        let ts = TrustScore::new("nav");
        let att = TrustAttestation::new(&ts);
        assert!((att.min_signature_trust() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_trust_attestation_expiry() {
        let ts = TrustScore::new("nav");
        let mut att = TrustAttestation::new(&ts);
        att.created_at = 1000;
        assert!(att.is_expired(5000, 7000));
        assert!(!att.is_expired(5000, 3000));
    }

    #[test]
    fn test_i2i_envelope_new() {
        let ts = TrustScore::new("nav");
        let env = I2IEnvelope::with_trust_score(
            "alice", Some("bob"), I2IMessageKind::Request, b"hello".to_vec(), &ts,
        );
        assert_eq!(env.sender, "alice");
        assert_eq!(env.recipient.as_deref(), Some("bob"));
        assert_eq!(env.kind, I2IMessageKind::Request);
        assert!(!env.is_broadcast());
    }

    #[test]
    fn test_i2i_envelope_broadcast() {
        let ts = TrustScore::new("nav");
        let env = I2IEnvelope::with_trust_score(
            "alice", None, I2IMessageKind::Broadcast, b"announce".to_vec(), &ts,
        );
        assert!(env.is_broadcast());
    }

    #[test]
    fn test_i2i_envelope_relay() {
        let ts = TrustScore::new("nav");
        let mut env = I2IEnvelope::with_trust_score(
            "alice", Some("bob"), I2IMessageKind::Request, b"hello".to_vec(), &ts,
        );
        env.relay("relay1", 0.8, 0.7);
        assert_eq!(env.trust_attestation.hops, 1);
        assert_eq!(env.trust_attestation.signatures.len(), 1);
    }

    #[test]
    fn test_i2i_envelope_serialization() {
        let ts = TrustScore::new("nav");
        let env = I2IEnvelope::with_trust_score(
            "alice", Some("bob"), I2IMessageKind::Request, b"hello".to_vec(), &ts,
        );
        let bytes = env.to_json_bytes().unwrap();
        let decoded = I2IEnvelope::from_json_bytes(&bytes).unwrap();
        assert_eq!(decoded.sender, "alice");
        assert_eq!(decoded.recipient.as_deref(), Some("bob"));
        assert_eq!(decoded.kind, I2IMessageKind::Request);
    }

    #[test]
    fn test_wire_trust_score_roundtrip() {
        let mut ts = TrustScore::new("nav");
        ts.reward(1.0);
        ts.reward(1.0);
        let wire = WireTrustScore::from_score(&ts);
        assert_eq!(wire.positive, 2);
        let restored = wire.to_score();
        assert!((restored.value - ts.value).abs() < 0.001);
        assert_eq!(restored.context, "nav");
    }

    #[test]
    fn test_wire_trust_score_serialization() {
        let ts = TrustScore::new("nav");
        let wire = WireTrustScore::from_score(&ts);
        let bytes = wire.to_bytes().unwrap();
        let decoded = WireTrustScore::from_bytes(&bytes).unwrap();
        assert!((decoded.value - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_trust_aware_message() {
        let ts = TrustScore::new("nav");
        let msg = TrustAwareMessage::with_score(
            "test payload".to_string(), "alice", Some("bob"), &ts,
        );
        assert_eq!(msg.sender, "alice");
        assert_eq!(msg.recipient.as_deref(), Some("bob"));
        let (inner, trust) = msg.into_parts();
        assert_eq!(inner, "test payload");
        assert_eq!(trust.trust_context, "nav");
    }

    #[test]
    fn test_trust_aware_message_serialization() {
        let ts = TrustScore::new("nav");
        let msg = TrustAwareMessage::with_score(
            "data".to_string(), "alice", Some("bob"), &ts,
        );
        let bytes = msg.to_json_bytes().unwrap();
        let decoded: TrustAwareMessage<String> = TrustAwareMessage::from_json_bytes(&bytes).unwrap();
        assert_eq!(decoded.inner, "data");
        assert_eq!(decoded.sender, "alice");
    }

    #[test]
    fn test_protocol_header() {
        let header = I2IProtocolHeader::current("msg-123");
        assert_eq!(header.version, 1);
        assert!(header.trust_enabled);
        assert_eq!(header.message_id, "msg-123");
    }

    #[test]
    fn test_trust_signature_new() {
        let sig = TrustSignature::new("agent1", 0.75, 0.8);
        assert_eq!(sig.agent_id, "agent1");
        assert!((sig.trust_at_time - 0.75).abs() < 0.001);
        assert!(sig.timestamp > 0);
    }

    #[test]
    fn test_message_id() {
        let id = MessageId::new();
        assert!(id.as_str().starts_with("i2i-"));
        let display = format!("{}", id);
        assert_eq!(display, id.as_str());
    }

    #[test]
    fn test_trust_attestation_for_agent() {
        let mut registry = TrustRegistry::new();
        registry.interact("alice", "bob", "nav", true);
        registry.interact("alice", "bob", "nav", true);
        let att = TrustAttestation::for_agent(&registry, "alice", "nav");
        assert!(att.sender_trust_score > 0.5);
    }
}
