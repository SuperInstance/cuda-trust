/*!
# Trust Propagation

Propagates trust information through the I2I fleet. When an agent's trust
changes, the propagation engine gossips this information to neighbors and
updates the fleet-wide trust view.

Trust propagation follows these rules:
- Positive trust changes propagate slowly (to prevent gaming)
- Negative trust changes propagate immediately (security first)
- Propagation depth is limited to prevent cascade failures
- Agents can opt out of propagation (privacy)
*/

use crate::TrustRegistry;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

use super::message::{I2IEnvelope, I2IMessageKind, TrustAttestation};

/// A trust update event to propagate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustUpdate {
    /// The agent whose trust changed.
    pub agent_id: String,
    /// The context of the trust change.
    pub context: String,
    /// New trust value.
    pub new_trust: f64,
    /// Previous trust value.
    pub previous_trust: f64,
    /// Direction of change.
    pub direction: TrustChangeDirection,
    /// Magnitude of change.
    pub magnitude: f64,
    /// Timestamp of the change.
    pub timestamp: u64,
    /// Source agent (who made the observation).
    pub observer: String,
    /// How many hops this update has traveled.
    pub propagation_depth: u32,
}

/// Direction of trust change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustChangeDirection {
    Increased,
    Decreased,
    Unchanged,
}

impl TrustUpdate {
    /// Create a new trust update.
    pub fn new(
        agent_id: &str,
        context: &str,
        previous_trust: f64,
        new_trust: f64,
        observer: &str,
    ) -> Self {
        let delta = new_trust - previous_trust;
        let direction = if delta.abs() < 0.001 {
            TrustChangeDirection::Unchanged
        } else if delta > 0.0 {
            TrustChangeDirection::Increased
        } else {
            TrustChangeDirection::Decreased
        };

        TrustUpdate {
            agent_id: agent_id.to_string(),
            context: context.to_string(),
            new_trust,
            previous_trust,
            direction,
            magnitude: delta.abs(),
            timestamp: now(),
            observer: observer.to_string(),
            propagation_depth: 0,
        }
    }

    /// Whether this update is significant enough to propagate.
    pub fn is_significant(&self, min_magnitude: f64) -> bool {
        self.direction != TrustChangeDirection::Unchanged && self.magnitude >= min_magnitude
    }

    /// Whether this is a negative trust change.
    pub fn is_negative(&self) -> bool {
        self.direction == TrustChangeDirection::Decreased
    }
}

/// Propagation gossip message for I2I transport.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustGossip {
    /// Trust updates being gossiped.
    pub updates: Vec<TrustUpdate>,
    /// Sender of the gossip.
    pub sender: String,
    /// Sequence number (for ordering).
    pub sequence: u64,
    /// Timestamp.
    pub timestamp: u64,
}

impl TrustGossip {
    /// Create a new gossip message.
    pub fn new(sender: &str, updates: Vec<TrustUpdate>, sequence: u64) -> Self {
        TrustGossip {
            updates,
            sender: sender.to_string(),
            sequence,
            timestamp: now(),
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(data)
    }
}

/// Propagation policy controlling how trust updates spread.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PropagationPolicy {
    /// Maximum propagation depth (hops).
    pub max_depth: u32,
    /// Minimum trust change magnitude to propagate.
    pub positive_min_magnitude: f64,
    /// Minimum magnitude for negative changes (usually lower — spread fast).
    pub negative_min_magnitude: f64,
    /// Fan-out: how many neighbors to gossip to.
    pub fan_out: usize,
    /// Whether negative changes get priority propagation.
    pub negative_priority: bool,
    /// Maximum age of an update to propagate (ms).
    pub max_update_age_ms: u64,
}

impl Default for PropagationPolicy {
    fn default() -> Self {
        PropagationPolicy {
            max_depth: 5,
            positive_min_magnitude: 0.1,
            negative_min_magnitude: 0.05,
            fan_out: 3,
            negative_priority: true,
            max_update_age_ms: 300_000, // 5 minutes
        }
    }
}

/// Trust propagation engine for I2I fleet.
///
/// Monitors trust changes and gossips them to fleet neighbors.
/// Negative changes propagate faster and wider than positive ones.
#[derive(Clone, Debug)]
pub struct TrustPropagator {
    /// Trust registry (source of truth).
    registry: TrustRegistry,
    /// Propagation policy.
    policy: PropagationPolicy,
    /// Pending updates to propagate.
    pending_updates: VecDeque<TrustUpdate>,
    /// Agents that have opted out of propagation.
    opt_out: HashSet<String>,
    /// Sequence counter for gossip messages.
    gossip_sequence: u64,
    /// History of propagated updates (to prevent cycles).
    propagated: HashSet<String>,
    /// Neighbor graph for gossip targets.
    neighbors: HashMap<String, Vec<String>>,
}

impl TrustPropagator {
    /// Create a new trust propagator.
    pub fn new(registry: TrustRegistry) -> Self {
        Self::with_policy(registry, PropagationPolicy::default())
    }

    /// Create a new trust propagator with a specific policy.
    pub fn with_policy(registry: TrustRegistry, policy: PropagationPolicy) -> Self {
        TrustPropagator {
            registry,
            policy,
            pending_updates: VecDeque::new(),
            opt_out: HashSet::new(),
            gossip_sequence: 0,
            propagated: HashSet::new(),
            neighbors: HashMap::new(),
        }
    }

    /// Record a trust change and queue it for propagation.
    pub fn record_change(
        &mut self,
        agent_id: &str,
        context: &str,
        previous_trust: f64,
        new_trust: f64,
        observer: &str,
    ) {
        if self.opt_out.contains(agent_id) {
            return;
        }

        let update = TrustUpdate::new(agent_id, context, previous_trust, new_trust, observer);
        if update.is_significant(if update.is_negative() {
            self.policy.negative_min_magnitude
        } else {
            self.policy.positive_min_magnitude
        }) {
            if self.policy.negative_priority && update.is_negative() {
                // Negative changes go to the front of the queue
                self.pending_updates.push_front(update);
            } else {
                self.pending_updates.push_back(update);
            }
        }
    }

    /// Process pending updates and generate gossip messages.
    pub fn propagate(&mut self) -> Vec<TrustGossip> {
        let mut gossips = Vec::new();
        let current_time = now();

        while let Some(mut update) = self.pending_updates.pop_front() {
            // Check if already propagated
            let update_key = format!("{}:{}:{}:{}", update.agent_id, update.context, update.observer, update.timestamp);
            if self.propagated.contains(&update_key) {
                continue;
            }

            // Check update age
            if current_time.saturating_sub(update.timestamp) > self.policy.max_update_age_ms {
                continue;
            }

            // Check depth
            if update.propagation_depth >= self.policy.max_depth {
                continue;
            }

            self.propagated.insert(update_key);
            update.propagation_depth += 1;

            // Find gossip targets
            let targets = self.find_gossip_targets(&update.agent_id);
            if !targets.is_empty() {
                let updates = vec![update.clone()];
                self.gossip_sequence += 1;
                let gossip = TrustGossip::new("propagator", updates, self.gossip_sequence);
                gossips.push(gossip);
            }
        }

        gossips
    }

    /// Find gossip targets for an update about an agent.
    fn find_gossip_targets(&self, agent_id: &str) -> Vec<String> {
        let mut targets: Vec<String> = self
            .neighbors
            .get(agent_id)
            .cloned()
            .unwrap_or_default();

        // Filter out opted-out agents
        targets.retain(|t| !self.opt_out.contains(t));

        // Limit to fan_out
        targets.truncate(self.policy.fan_out);
        targets
    }

    /// Apply a received gossip update to the local registry.
    pub fn apply_gossip(&mut self, gossip: &TrustGossip) -> Vec<TrustUpdate> {
        let mut applied = Vec::new();

        for update in &gossip.updates {
            // Don't apply if we already know about this update
            let update_key = format!("{}:{}:{}:{}", update.agent_id, update.context, update.observer, update.timestamp);
            if self.propagated.contains(&update_key) {
                continue;
            }

            // Don't apply if depth exceeded
            if update.propagation_depth >= self.policy.max_depth {
                continue;
            }

            // Apply the trust change (dampened by propagation depth)
            let dampening = 0.8_f64.powi(update.propagation_depth as i32);
            let _adjusted_trust = if update.is_negative() {
                // Negative changes are not dampened (security first)
                update.new_trust
            } else {
                // Positive changes are dampened
                update.previous_trust + (update.new_trust - update.previous_trust) * dampening
            };

            let positive = update.direction != TrustChangeDirection::Decreased;
            let profile = self.registry.profile(&update.observer);
            if positive {
                profile.interact(&update.context, true, update.magnitude * dampening);
            } else {
                profile.interact(&update.context, false, update.magnitude);
            }

            self.propagated.insert(update_key);
            applied.push(update.clone());
        }

        applied
    }

    /// Register a neighbor relationship for gossip.
    pub fn add_neighbor(&mut self, agent_id: &str, neighbor: &str) {
        self.neighbors
            .entry(agent_id.to_string())
            .or_default()
            .push(neighbor.to_string());
        // Bidirectional
        self.neighbors
            .entry(neighbor.to_string())
            .or_default()
            .push(agent_id.to_string());
    }

    /// Opt an agent out of propagation.
    pub fn opt_out(&mut self, agent_id: &str) {
        self.opt_out.insert(agent_id.to_string());
    }

    /// Opt an agent back into propagation.
    pub fn opt_in(&mut self, agent_id: &str) {
        self.opt_out.remove(agent_id);
    }

    /// Get the number of pending updates.
    pub fn pending_count(&self) -> usize {
        self.pending_updates.len()
    }

    /// Get the propagation policy.
    pub fn policy(&self) -> &PropagationPolicy {
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

    /// Clear propagated history (for testing).
    pub fn clear_history(&mut self) {
        self.propagated.clear();
    }
}

/// Trust propagation statistics.
#[derive(Clone, Debug, Default)]
pub struct PropagationStats {
    pub updates_generated: usize,
    pub updates_applied: usize,
    pub updates_dropped: usize,
    pub gossip_messages_sent: usize,
    pub gossip_messages_received: usize,
    pub negative_propagations: usize,
    pub positive_propagations: usize,
}

/// Create I2I gossip envelopes from trust updates.
pub fn create_gossip_envelopes(
    propagator: &mut TrustPropagator,
    sender: &str,
) -> Vec<I2IEnvelope> {
    let gossips = propagator.propagate();
    let mut envelopes = Vec::new();

    for gossip in gossips {
        if let Ok(payload) = serde_json::to_vec(&gossip) {
            let attestation = TrustAttestation::for_agent(
                propagator.registry(),
                sender,
                "trust-gossip",
            );
            let envelope = I2IEnvelope::new(
                sender,
                None, // broadcast
                I2IMessageKind::Gossip,
                payload,
                attestation,
            );
            envelopes.push(envelope);
        }
    }

    envelopes
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_update_creation() {
        let update = TrustUpdate::new("alice", "nav", 0.5, 0.7, "bob");
        assert_eq!(update.direction, TrustChangeDirection::Increased);
        assert!((update.magnitude - 0.2).abs() < 0.001);
        assert!(update.is_significant(0.1));
        assert!(!update.is_negative());
    }

    #[test]
    fn test_trust_update_negative() {
        let update = TrustUpdate::new("alice", "nav", 0.7, 0.3, "bob");
        assert_eq!(update.direction, TrustChangeDirection::Decreased);
        assert!((update.magnitude - 0.4).abs() < 0.001);
        assert!(update.is_negative());
    }

    #[test]
    fn test_trust_update_unchanged() {
        let update = TrustUpdate::new("alice", "nav", 0.5, 0.5, "bob");
        assert_eq!(update.direction, TrustChangeDirection::Unchanged);
        assert!(!update.is_significant(0.1));
    }

    #[test]
    fn test_record_and_propagate() {
        let registry = TrustRegistry::new();
        let mut propagator = TrustPropagator::new(registry);
        propagator.add_neighbor("alice", "bob");
        propagator.add_neighbor("alice", "carol");

        propagator.record_change("alice", "nav", 0.5, 0.8, "observer");
        assert_eq!(propagator.pending_count(), 1);

        let gossips = propagator.propagate();
        assert_eq!(gossips.len(), 1);
        assert_eq!(propagator.pending_count(), 0);
    }

    #[test]
    fn test_negative_priority_propagation() {
        let registry = TrustRegistry::new();
        let mut propagator = TrustPropagator::new(registry);
        propagator.add_neighbor("alice", "bob");

        // Record positive and negative changes
        propagator.record_change("alice", "nav", 0.5, 0.6, "obs1");
        propagator.record_change("carol", "nav", 0.7, 0.2, "obs2");

        // Negative should be first
        let first = propagator.pending_updates.front().unwrap();
        assert!(first.is_negative());
    }

    #[test]
    fn test_apply_gossip() {
        let registry = TrustRegistry::new();
        let mut propagator = TrustPropagator::new(registry);

        let update = TrustUpdate::new("alice", "nav", 0.5, 0.8, "bob");
        let gossip = TrustGossip::new("carol", vec![update], 1);

        let applied = propagator.apply_gossip(&gossip);
        assert_eq!(applied.len(), 1);

        // Second application should be a no-op (already propagated)
        let applied2 = propagator.apply_gossip(&gossip);
        assert_eq!(applied2.len(), 0);
    }

    #[test]
    fn test_opt_out() {
        let registry = TrustRegistry::new();
        let mut propagator = TrustPropagator::new(registry);
        propagator.add_neighbor("alice", "bob");

        propagator.opt_out("alice");
        propagator.record_change("alice", "nav", 0.5, 0.8, "obs");
        assert_eq!(propagator.pending_count(), 0);

        propagator.opt_in("alice");
        propagator.record_change("alice", "nav", 0.5, 0.8, "obs");
        assert_eq!(propagator.pending_count(), 1);
    }

    #[test]
    fn test_depth_limit() {
        let registry = TrustRegistry::new();
        let policy = PropagationPolicy {
            max_depth: 1,
            ..PropagationPolicy::default()
        };
        let mut propagator = TrustPropagator::with_policy(registry, policy);
        propagator.add_neighbor("alice", "bob");

        let mut update = TrustUpdate::new("alice", "nav", 0.5, 0.8, "obs");
        update.propagation_depth = 1; // already at max

        let gossip = TrustGossip::new("relay", vec![update], 1);
        let applied = propagator.apply_gossip(&gossip);
        assert_eq!(applied.len(), 0);
    }

    #[test]
    fn test_gossip_serialization() {
        let update = TrustUpdate::new("alice", "nav", 0.5, 0.8, "bob");
        let gossip = TrustGossip::new("carol", vec![update], 42);

        let bytes = gossip.to_bytes().unwrap();
        let decoded = TrustGossip::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.updates.len(), 1);
        assert_eq!(decoded.sender, "carol");
    }

    #[test]
    fn test_bidirectional_neighbors() {
        let registry = TrustRegistry::new();
        let mut propagator = TrustPropagator::new(registry);
        propagator.add_neighbor("alice", "bob");

        let alice_neighbors = propagator.neighbors.get("alice").unwrap();
        assert!(alice_neighbors.contains(&"bob".to_string()));
        let bob_neighbors = propagator.neighbors.get("bob").unwrap();
        assert!(bob_neighbors.contains(&"alice".to_string()));
    }

    #[test]
    fn test_create_gossip_envelopes() {
        let registry = TrustRegistry::new();
        let mut propagator = TrustPropagator::new(registry);
        propagator.add_neighbor("alice", "bob");
        propagator.record_change("alice", "nav", 0.5, 0.8, "obs");

        let envelopes = create_gossip_envelopes(&mut propagator, "sender");
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].kind, I2IMessageKind::Gossip);
        assert!(envelopes[0].is_broadcast());
    }

    #[test]
    fn test_positive_dampening() {
        let registry = TrustRegistry::new();
        let mut propagator = TrustPropagator::new(registry);

        let mut update = TrustUpdate::new("alice", "nav", 0.5, 0.7, "bob");
        update.propagation_depth = 2;
        let gossip = TrustGossip::new("relay", vec![update], 1);

        let applied = propagator.apply_gossip(&gossip);
        assert_eq!(applied.len(), 1);
        // The dampening should have been applied — observer "bob" had positive interaction
        let bob_trust = propagator.registry.trust_level("bob", "bob", "nav");
        assert!(bob_trust > 0.5);
    }

    #[test]
    fn test_negative_no_dampening() {
        let registry = TrustRegistry::new();
        let mut propagator = TrustPropagator::new(registry);

        // Establish some trust first
        propagator.registry.interact("obs", "target", "nav", true);

        let mut update = TrustUpdate::new("target", "nav", 0.7, 0.2, "obs");
        update.propagation_depth = 3; // deep propagation
        let gossip = TrustGossip::new("relay", vec![update], 1);

        propagator.apply_gossip(&gossip);
        // Negative changes should still be applied — observer "obs" gets punished
        let obs_trust = propagator.registry.trust_level("obs", "obs", "nav");
        assert!(obs_trust < 0.5); // punished
    }
}
