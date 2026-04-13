/*!
# Trust Validation Middleware

Middleware that intercepts I2I messages and validates their trust attestation
before allowing them through. Messages below the trust threshold are rejected
or quarantined.

This is the core security layer of the I2I fleet protocol.
*/

use crate::TrustRegistry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::message::{I2IEnvelope, I2IMessageKind};

/// Reason a message was rejected by trust validation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TrustRejectionReason {
    /// Sender's trust score is below the threshold.
    BelowThreshold {
        required: f64,
        actual: f64,
    },
    /// Message attestation has expired.
    Expired {
        age_ms: u64,
        ttl_ms: u64,
    },
    /// Sender is not known to the trust registry.
    UnknownAgent {
        agent_id: String,
    },
    /// Trust chain has too many hops.
    TooManyHops {
        hops: u32,
        max: u32,
    },
    /// Chain trust degraded below acceptable level.
    ChainTrustDegraded {
        chain_trust: f64,
        min_required: f64,
    },
    /// Trust context mismatch.
    ContextMismatch {
        expected: String,
        actual: String,
    },
}

impl std::fmt::Display for TrustRejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustRejectionReason::BelowThreshold { required, actual } => {
                write!(f, "trust {} below threshold {}", actual, required)
            }
            TrustRejectionReason::Expired { age_ms, ttl_ms } => {
                write!(f, "attestation expired: age {}ms > ttl {}ms", age_ms, ttl_ms)
            }
            TrustRejectionReason::UnknownAgent { agent_id } => {
                write!(f, "unknown agent: {}", agent_id)
            }
            TrustRejectionReason::TooManyHops { hops, max } => {
                write!(f, "too many hops: {} > max {}", hops, max)
            }
            TrustRejectionReason::ChainTrustDegraded { chain_trust, min_required } => {
                write!(f, "chain trust {} below minimum {}", chain_trust, min_required)
            }
            TrustRejectionReason::ContextMismatch { expected, actual } => {
                write!(f, "context mismatch: expected {}, got {}", expected, actual)
            }
        }
    }
}

/// Result of trust validation.
#[derive(Clone, Debug)]
pub enum TrustValidationResult {
    /// Message passes trust validation.
    Accept,
    /// Message is rejected with a reason.
    Reject(TrustRejectionReason),
    /// Message is quarantined for review.
    Quarantine {
        reason: String,
        envelope: I2IEnvelope,
    },
}

/// Trust validation policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustPolicy {
    /// Minimum trust score to accept a message.
    pub min_trust: f64,
    /// Maximum number of relay hops.
    pub max_hops: u32,
    /// Attestation TTL in milliseconds.
    pub attestation_ttl_ms: u64,
    /// Minimum chain trust to accept a relayed message.
    pub min_chain_trust: f64,
    /// Whether to require the sender to be known.
    pub require_known_sender: bool,
    /// Required trust context (None = any).
    pub required_context: Option<String>,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        TrustPolicy {
            min_trust: 0.3,
            max_hops: 10,
            attestation_ttl_ms: 300_000, // 5 minutes
            min_chain_trust: 0.1,
            require_known_sender: false,
            required_context: None,
        }
    }
}

impl TrustPolicy {
    /// Create a strict policy (high trust threshold).
    pub fn strict() -> Self {
        TrustPolicy {
            min_trust: 0.7,
            max_hops: 5,
            attestation_ttl_ms: 60_000, // 1 minute
            min_chain_trust: 0.3,
            require_known_sender: true,
            required_context: None,
        }
    }

    /// Create a permissive policy (low trust threshold).
    pub fn permissive() -> Self {
        TrustPolicy {
            min_trust: 0.1,
            max_hops: 20,
            attestation_ttl_ms: 600_000, // 10 minutes
            min_chain_trust: 0.01,
            require_known_sender: false,
            required_context: None,
        }
    }
}

/// Quarantined message entry.
#[derive(Clone, Debug)]
pub struct QuarantinedMessage {
    pub envelope: I2IEnvelope,
    pub reason: String,
    pub quarantined_at: u64,
}

/// Trust validation middleware for I2I messages.
///
/// Intercepts messages and validates trust attestation against policy.
/// Messages that fail validation can be rejected or quarantined.
#[derive(Clone, Debug)]
pub struct TrustMiddleware {
    /// Trust registry for lookups.
    registry: TrustRegistry,
    /// Validation policy.
    policy: TrustPolicy,
    /// Quarantined messages.
    quarantine: HashMap<String, QuarantinedMessage>,
    /// Track message IDs to prevent replay.
    seen_messages: HashMap<String, u64>,
    /// Maximum age for seen message cache.
    seen_ttl_ms: u64,
}

impl TrustMiddleware {
    /// Create a new middleware with default policy.
    pub fn new(registry: TrustRegistry) -> Self {
        Self::with_policy(registry, TrustPolicy::default())
    }

    /// Create a new middleware with a specific policy.
    pub fn with_policy(registry: TrustRegistry, policy: TrustPolicy) -> Self {
        TrustMiddleware {
            registry,
            policy,
            quarantine: HashMap::new(),
            seen_messages: HashMap::new(),
            seen_ttl_ms: 300_000,
        }
    }

    /// Validate an I2I envelope against trust policy.
    pub fn validate(&mut self, envelope: &I2IEnvelope) -> TrustValidationResult {
        let now_ms = Self::now();

        // Replay protection
        if let Some(&seen_at) = self.seen_messages.get(envelope.id.as_str()) {
            if now_ms.saturating_sub(seen_at) < self.seen_ttl_ms {
                return TrustValidationResult::Reject(TrustRejectionReason::Expired {
                    age_ms: now_ms - seen_at,
                    ttl_ms: self.seen_ttl_ms,
                });
            }
        }
        self.seen_messages.insert(envelope.id.0.clone(), now_ms);

        // Check attestation expiry
        if envelope.trust_attestation.is_expired(self.policy.attestation_ttl_ms, now_ms) {
            let age = now_ms.saturating_sub(envelope.trust_attestation.created_at);
            return TrustValidationResult::Reject(TrustRejectionReason::Expired {
                age_ms: age,
                ttl_ms: self.policy.attestation_ttl_ms,
            });
        }

        // Check sender trust
        let sender_trust = envelope.trust_attestation.sender_trust_score;
        if sender_trust < self.policy.min_trust {
            return TrustValidationResult::Reject(TrustRejectionReason::BelowThreshold {
                required: self.policy.min_trust,
                actual: sender_trust,
            });
        }

        // Check known sender requirement
        if self.policy.require_known_sender {
            if !self.registry.profiles.contains_key(&envelope.sender) {
                return TrustValidationResult::Reject(TrustRejectionReason::UnknownAgent {
                    agent_id: envelope.sender.clone(),
                });
            }
        }

        // Check hop count
        if envelope.trust_attestation.hops > self.policy.max_hops {
            return TrustValidationResult::Reject(TrustRejectionReason::TooManyHops {
                hops: envelope.trust_attestation.hops,
                max: self.policy.max_hops,
            });
        }

        // Check chain trust (only for relayed messages)
        if envelope.trust_attestation.hops > 0 {
            if envelope.trust_attestation.chain_trust < self.policy.min_chain_trust {
                return TrustValidationResult::Reject(TrustRejectionReason::ChainTrustDegraded {
                    chain_trust: envelope.trust_attestation.chain_trust,
                    min_required: self.policy.min_chain_trust,
                });
            }
        }

        // Check context requirement
        if let Some(ref required) = self.policy.required_context {
            if envelope.trust_context != *required {
                return TrustValidationResult::Reject(TrustRejectionReason::ContextMismatch {
                    expected: required.clone(),
                    actual: envelope.trust_context.clone(),
                });
            }
        }

        // Cross-check with registry if sender is known
        if let Some(profile) = self.registry.profiles.get(&envelope.sender) {
            if let Some(score) = profile.contexts.get(&envelope.trust_context) {
                // If the attestation trust is wildly different from registry, quarantine
                let diff = (envelope.trust_attestation.sender_trust_score - score.value).abs();
                if diff > 0.5 && score.confidence > 0.5 {
                    let reason = format!(
                        "trust attestation ({:.3}) diverges from registry ({:.3}) by {:.3}",
                        envelope.trust_attestation.sender_trust_score, score.value, diff
                    );
                    return TrustValidationResult::Quarantine {
                        reason,
                        envelope: envelope.clone(),
                    };
                }
            }
        }

        TrustValidationResult::Accept
    }

    /// Validate and also record the interaction in the registry.
    pub fn validate_and_record(
        &mut self,
        envelope: &I2IEnvelope,
        positive: bool,
    ) -> TrustValidationResult {
        let result = self.validate(envelope);
        if matches!(result, TrustValidationResult::Accept) {
            self.registry.interact(
                "i2i-middleware",
                &envelope.sender,
                &envelope.trust_context,
                positive,
            );
        }
        result
    }

    /// Quarantine a message manually.
    pub fn quarantine_message(&mut self, envelope: I2IEnvelope, reason: &str) {
        let entry = QuarantinedMessage {
            envelope,
            reason: reason.to_string(),
            quarantined_at: Self::now(),
        };
        self.quarantine.insert(entry.envelope.id.0.clone(), entry);
    }

    /// Release a quarantined message.
    pub fn release_quarantined(&mut self, message_id: &str) -> Option<I2IEnvelope> {
        self.quarantine.remove(message_id).map(|q| q.envelope)
    }

    /// Get all quarantined messages.
    pub fn quarantined_messages(&self) -> Vec<&QuarantinedMessage> {
        self.quarantine.values().collect()
    }

    /// Get the policy reference.
    pub fn policy(&self) -> &TrustPolicy {
        &self.policy
    }

    /// Get mutable access to the registry.
    pub fn registry_mut(&mut self) -> &mut TrustRegistry {
        &mut self.registry
    }

    /// Get reference to the registry.
    pub fn registry(&self) -> &TrustRegistry {
        &self.registry
    }

    /// Purge expired seen messages.
    pub fn purge_seen(&mut self) {
        let now_ms = Self::now();
        self.seen_messages.retain(|_, &mut seen_at| {
            now_ms.saturating_sub(seen_at) < self.seen_ttl_ms
        });
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Batch validation result for multiple messages.
#[derive(Clone, Debug)]
pub struct BatchValidationResult {
    pub accepted: Vec<I2IEnvelope>,
    pub rejected: Vec<(I2IEnvelope, TrustRejectionReason)>,
    pub quarantined: Vec<QuarantinedMessage>,
}

impl TrustMiddleware {
    /// Validate a batch of messages.
    pub fn validate_batch(&mut self, envelopes: Vec<I2IEnvelope>) -> BatchValidationResult {
        let mut result = BatchValidationResult {
            accepted: Vec::new(),
            rejected: Vec::new(),
            quarantined: Vec::new(),
        };

        for envelope in envelopes {
            match self.validate(&envelope) {
                TrustValidationResult::Accept => {
                    result.accepted.push(envelope);
                }
                TrustValidationResult::Reject(reason) => {
                    result.rejected.push((envelope, reason));
                }
                TrustValidationResult::Quarantine { reason, envelope: env } => {
                    result.quarantined.push(QuarantinedMessage {
                        envelope: env,
                        reason,
                        quarantined_at: Self::now(),
                    });
                }
            }
        }

        result
    }

    /// Count accepted messages in a batch.
    pub fn acceptance_rate(&self, results: &BatchValidationResult) -> f64 {
        let total = results.accepted.len()
            + results.rejected.len()
            + results.quarantined.len();
        if total == 0 {
            return 0.0;
        }
        results.accepted.len() as f64 / total as f64
    }
}

/// Filter that applies trust-based routing decisions.
#[derive(Clone, Debug)]
pub struct TrustFilter {
    /// Minimum trust to forward a broadcast.
    pub broadcast_trust_threshold: f64,
    /// Minimum trust for direct messages.
    pub direct_trust_threshold: f64,
    /// Whether gossip messages bypass trust checks.
    pub gossip_exempt: bool,
}

impl Default for TrustFilter {
    fn default() -> Self {
        TrustFilter {
            broadcast_trust_threshold: 0.2,
            direct_trust_threshold: 0.3,
            gossip_exempt: true,
        }
    }
}

impl TrustFilter {
    /// Check if a message kind should bypass trust filtering.
    pub fn should_bypass(&self, kind: &I2IMessageKind) -> bool {
        self.gossip_exempt && *kind == I2IMessageKind::Gossip
    }

    /// Get the trust threshold for a message kind.
    pub fn threshold_for(&self, kind: &I2IMessageKind) -> f64 {
        match kind {
            I2IMessageKind::Broadcast => self.broadcast_trust_threshold,
            I2IMessageKind::Gossip => 0.0, // exempt
            I2IMessageKind::Heartbeat => 0.1,
            I2IMessageKind::TrustAttestation => 0.0, // trust info is always welcome
            _ => self.direct_trust_threshold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustScore;

    fn make_envelope(sender: &str, trust_value: f64) -> I2IEnvelope {
        let mut ts = TrustScore::new("nav");
        ts.value = trust_value;
        ts.confidence = 0.8;
        I2IEnvelope::with_trust_score(sender, Some("receiver"), I2IMessageKind::Request, vec![], &ts)
    }

    #[test]
    fn test_accept_valid_message() {
        let registry = TrustRegistry::new();
        let mut mw = TrustMiddleware::new(registry);
        let env = make_envelope("alice", 0.8);
        let result = mw.validate(&env);
        assert!(matches!(result, TrustValidationResult::Accept));
    }

    #[test]
    fn test_reject_low_trust() {
        let registry = TrustRegistry::new();
        let mut mw = TrustMiddleware::new(registry);
        let env = make_envelope("alice", 0.1);
        let result = mw.validate(&env);
        assert!(matches!(
            result,
            TrustValidationResult::Reject(TrustRejectionReason::BelowThreshold { .. })
        ));
    }

    #[test]
    fn test_reject_too_many_hops() {
        let registry = TrustRegistry::new();
        let policy = TrustPolicy {
            max_hops: 2,
            ..TrustPolicy::default()
        };
        let mut mw = TrustMiddleware::with_policy(registry, policy);
        let mut env = make_envelope("alice", 0.8);
        env.trust_attestation.add_hop("r1", 0.9, 0.9);
        env.trust_attestation.add_hop("r2", 0.9, 0.9);
        env.trust_attestation.add_hop("r3", 0.9, 0.9);
        let result = mw.validate(&env);
        assert!(matches!(
            result,
            TrustValidationResult::Reject(TrustRejectionReason::TooManyHops { .. })
        ));
    }

    #[test]
    fn test_reject_chain_trust_degraded() {
        let registry = TrustRegistry::new();
        let policy = TrustPolicy {
            min_chain_trust: 0.5,
            ..TrustPolicy::default()
        };
        let mut mw = TrustMiddleware::with_policy(registry, policy);
        let mut env = make_envelope("alice", 0.8);
        // Add a low-trust hop that degrades chain
        env.trust_attestation.add_hop("bad_relay", 0.2, 0.5);
        let result = mw.validate(&env);
        assert!(matches!(
            result,
            TrustValidationResult::Reject(TrustRejectionReason::ChainTrustDegraded { .. })
        ));
    }

    #[test]
    fn test_strict_policy() {
        let registry = TrustRegistry::new();
        let mut mw = TrustMiddleware::with_policy(registry, TrustPolicy::strict());
        let env = make_envelope("alice", 0.5); // below strict 0.7
        let result = mw.validate(&env);
        assert!(matches!(
            result,
            TrustValidationResult::Reject(TrustRejectionReason::BelowThreshold { .. })
        ));
    }

    #[test]
    fn test_permissive_policy() {
        let registry = TrustRegistry::new();
        let mut mw = TrustMiddleware::with_policy(registry, TrustPolicy::permissive());
        let env = make_envelope("alice", 0.15); // above permissive 0.1
        let result = mw.validate(&env);
        assert!(matches!(result, TrustValidationResult::Accept));
    }

    #[test]
    fn test_require_known_sender() {
        let mut registry = TrustRegistry::new();
        // Register bob but not mallory
        registry.profile("bob");
        let policy = TrustPolicy {
            require_known_sender: true,
            ..TrustPolicy::default()
        };
        let mut mw = TrustMiddleware::with_policy(registry, policy);

        // Bob should be accepted
        let env_bob = make_envelope("bob", 0.8);
        assert!(matches!(mw.validate(&env_bob), TrustValidationResult::Accept));

        // Mallory should be rejected
        let env_mallory = make_envelope("mallory", 0.8);
        assert!(matches!(
            mw.validate(&env_mallory),
            TrustValidationResult::Reject(TrustRejectionReason::UnknownAgent { .. })
        ));
    }

    #[test]
    fn test_context_mismatch() {
        let registry = TrustRegistry::new();
        let policy = TrustPolicy {
            required_context: Some("security".to_string()),
            ..TrustPolicy::default()
        };
        let mut mw = TrustMiddleware::with_policy(registry, policy);
        // envelope has "nav" context
        let env = make_envelope("alice", 0.8);
        let result = mw.validate(&env);
        assert!(matches!(
            result,
            TrustValidationResult::Reject(TrustRejectionReason::ContextMismatch { .. })
        ));
    }

    #[test]
    fn test_quarantine_message() {
        let registry = TrustRegistry::new();
        let mut mw = TrustMiddleware::new(registry);
        let env = make_envelope("alice", 0.8);
        mw.quarantine_message(env.clone(), "suspicious payload");
        assert_eq!(mw.quarantined_messages().len(), 1);
        let released = mw.release_quarantined(env.id.as_str());
        assert!(released.is_some());
        assert_eq!(mw.quarantined_messages().len(), 0);
    }

    #[test]
    fn test_validate_and_record() {
        let registry = TrustRegistry::new();
        let mut mw = TrustMiddleware::new(registry);
        let env = make_envelope("alice", 0.8);
        let result = mw.validate_and_record(&env, true);
        assert!(matches!(result, TrustValidationResult::Accept));
        // Check interaction was recorded
        let trust = mw.registry.trust_level("i2i-middleware", "alice", "nav");
        assert!(trust > 0.5); // should have been rewarded
    }

    #[test]
    fn test_batch_validation() {
        let registry = TrustRegistry::new();
        let mut mw = TrustMiddleware::new(registry);
        let envelopes = vec![
            make_envelope("alice", 0.8),
            make_envelope("bob", 0.1),   // rejected
            make_envelope("carol", 0.5),
        ];
        let result = mw.validate_batch(envelopes);
        assert_eq!(result.accepted.len(), 2);
        assert_eq!(result.rejected.len(), 1);
    }

    #[test]
    fn test_acceptance_rate() {
        let registry = TrustRegistry::new();
        let mw = TrustMiddleware::new(registry);
        let result = BatchValidationResult {
            accepted: vec![],
            rejected: vec![],
            quarantined: vec![],
        };
        assert!((mw.acceptance_rate(&result)).abs() < 0.001);

        let result2 = BatchValidationResult {
            accepted: vec![make_envelope("a", 0.8)],
            rejected: vec![(make_envelope("b", 0.1), TrustRejectionReason::BelowThreshold { required: 0.3, actual: 0.1 })],
            quarantined: vec![],
        };
        assert!((mw.acceptance_rate(&result2) - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_trust_filter() {
        let filter = TrustFilter::default();
        assert!(filter.should_bypass(&I2IMessageKind::Gossip));
        assert!(!filter.should_bypass(&I2IMessageKind::Request));
        assert!((filter.threshold_for(&I2IMessageKind::Broadcast) - 0.2).abs() < 0.001);
        assert!((filter.threshold_for(&I2IMessageKind::Request) - 0.3).abs() < 0.001);
        assert!((filter.threshold_for(&I2IMessageKind::Gossip)).abs() < 0.001);
        assert!((filter.threshold_for(&I2IMessageKind::Heartbeat) - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_rejection_display() {
        let r = TrustRejectionReason::BelowThreshold { required: 0.5, actual: 0.2 };
        let s = format!("{}", r);
        assert!(s.contains("0.2") && s.contains("0.5"));
    }

    #[test]
    fn test_replay_protection() {
        let registry = TrustRegistry::new();
        let mut mw = TrustMiddleware::new(registry);
        let env = make_envelope("alice", 0.8);
        // First time: accept
        assert!(matches!(mw.validate(&env), TrustValidationResult::Accept));
        // Second time with same ID: reject (replay)
        // Note: replay detection uses a short TTL so the same-second validation
        // may trigger. But in our case, seen_messages TTL is 300s so it will detect.
        let result = mw.validate(&env);
        // The replay detection fires because the message was just seen.
        assert!(matches!(result, TrustValidationResult::Reject(TrustRejectionReason::Expired { .. })));
    }
}
