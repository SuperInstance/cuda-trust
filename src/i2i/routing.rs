/*!
# Trust-Aware Message Routing

Routes I2I messages based on trust scores. High-trust agents get priority
routing, low-trust agents are deprioritized or routed through verification
hops.

Trust-based routing ensures that the fleet's communication fabric is
self-healing: compromised or low-trust agents are naturally isolated.
*/

use crate::TrustRegistry;
use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, HashMap, HashSet};

use super::message::{I2IEnvelope, I2IMessageKind};

/// A routing decision for a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Deliver directly to the recipient.
    Direct,
    /// Route through a trusted relay.
    ViaRelay { relay_agent: String },
    /// Drop the message (insufficient trust).
    Drop { reason: String },
    /// Queue for later delivery (e.g., trust pending).
    Queue,
    /// Broadcast to all reachable agents.
    Broadcast,
}

/// Routing priority based on trust.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoutingPriority {
    /// Agent ID.
    pub agent_id: String,
    /// Trust score used for routing.
    pub trust_score: f64,
    /// Confidence of the trust score.
    pub confidence: f64,
    /// Computed priority (higher = more important).
    pub priority: f64,
    /// Estimated latency in ms.
    pub estimated_latency_ms: u64,
}

impl Eq for RoutingPriority {}

impl Ord for RoutingPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.partial_cmp(&other.priority).unwrap_or(std::cmp::Ordering::Equal)
    }
}

impl PartialOrd for RoutingPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Routing table entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingEntry {
    pub agent_id: String,
    pub trust_score: f64,
    pub last_seen: u64,
    pub capabilities: HashSet<String>,
    pub is_relay: bool,
}

/// Trust-aware message router for the I2I fleet.
///
/// Combines trust scores with routing logic to make intelligent
/// forwarding decisions. Messages from trusted agents get priority
/// routing; messages from unknown or low-trust agents are deprioritized.
#[derive(Clone, Debug)]
pub struct TrustRouter {
    /// Trust registry for trust lookups.
    registry: TrustRegistry,
    /// Routing table: agent_id -> routing entry.
    routing_table: HashMap<String, RoutingEntry>,
    /// Trust context for routing decisions.
    routing_context: String,
    /// Minimum trust to allow direct routing.
    direct_trust_threshold: f64,
    /// Minimum trust to allow relayed routing.
    relay_trust_threshold: f64,
    /// Maximum number of relays in a path.
    max_relays: u32,
    /// Trust score cache for fast lookups.
    trust_cache: HashMap<String, f64>,
}

impl TrustRouter {
    /// Create a new trust router.
    pub fn new(registry: TrustRegistry, routing_context: &str) -> Self {
        TrustRouter {
            registry,
            routing_table: HashMap::new(),
            routing_context: routing_context.to_string(),
            direct_trust_threshold: 0.5,
            relay_trust_threshold: 0.3,
            max_relays: 3,
            trust_cache: HashMap::new(),
        }
    }

    /// Set trust thresholds.
    pub fn with_thresholds(mut self, direct: f64, relay: f64) -> Self {
        self.direct_trust_threshold = direct;
        self.relay_trust_threshold = relay;
        self
    }

    /// Register an agent in the routing table.
    pub fn register_agent(
        &mut self,
        agent_id: &str,
        capabilities: HashSet<String>,
        is_relay: bool,
    ) {
        let trust = self.get_trust(agent_id);
        let entry = RoutingEntry {
            agent_id: agent_id.to_string(),
            trust_score: trust,
            last_seen: now(),
            capabilities,
            is_relay,
        };
        self.routing_table.insert(agent_id.to_string(), entry);
    }

    /// Make a routing decision for a message.
    pub fn route(&self, envelope: &I2IEnvelope) -> RoutingDecision {
        let sender_trust = envelope.trust_attestation.sender_trust_score;

        // Broadcasts always go through
        if envelope.is_broadcast() {
            return RoutingDecision::Broadcast;
        }

        // Check if recipient is directly reachable
        if let Some(ref recipient) = envelope.recipient {
            // If recipient is in routing table and sender has enough trust
            if self.routing_table.contains_key(recipient) {
                if sender_trust >= self.direct_trust_threshold {
                    return RoutingDecision::Direct;
                }
                if sender_trust >= self.relay_trust_threshold {
                    // Find a trusted relay
                    if let Some(relay) = self.find_trusted_relay(&envelope.sender, recipient) {
                        return RoutingDecision::ViaRelay { relay_agent: relay };
                    }
                }
                // Below relay threshold: queue or drop
                if sender_trust >= self.relay_trust_threshold * 0.5 {
                    return RoutingDecision::Queue;
                }
                return RoutingDecision::Drop {
                    reason: format!(
                        "sender trust {} below minimum {}",
                        sender_trust, self.relay_trust_threshold
                    ),
                };
            }
            // Recipient not in routing table — try relay
            if let Some(relay) = self.find_trusted_relay(&envelope.sender, recipient) {
                return RoutingDecision::ViaRelay { relay_agent: relay };
            }
            return RoutingDecision::Drop {
                reason: format!("no route to {}", recipient),
            };
        }

        RoutingDecision::Drop {
            reason: "no recipient specified".to_string(),
        }
    }

    /// Find the most trusted relay between two agents.
    fn find_trusted_relay(&self, _from: &str, _to: &str) -> Option<String> {
        self.routing_table
            .iter()
            .filter(|(_, entry)| entry.is_relay && entry.trust_score >= self.relay_trust_threshold)
            .max_by(|a, b| a.1.trust_score.partial_cmp(&b.1.trust_score).unwrap())
            .map(|(id, _)| id.clone())
    }

    /// Get trust score for an agent (with caching).
    fn get_trust(&self, agent_id: &str) -> f64 {
        if let Some(&cached) = self.trust_cache.get(agent_id) {
            return cached;
        }
        self.registry
            .trust_level(agent_id, agent_id, &self.routing_context)
    }

    /// Update trust cache for an agent.
    pub fn update_trust_cache(&mut self, agent_id: &str) {
        let trust = self.registry
            .trust_level(agent_id, agent_id, &self.routing_context);
        self.trust_cache.insert(agent_id.to_string(), trust);
        if let Some(entry) = self.routing_table.get_mut(agent_id) {
            entry.trust_score = trust;
            entry.last_seen = now();
        }
    }

    /// Refresh all trust caches.
    pub fn refresh_caches(&mut self) {
        let agent_ids: Vec<String> = self.routing_table.keys().cloned().collect();
        for id in agent_ids {
            self.update_trust_cache(&id);
        }
    }

    /// Get routing priorities for all agents (for priority queue).
    pub fn get_priorities(&self) -> Vec<RoutingPriority> {
        self.routing_table
            .iter()
            .map(|(_, entry)| {
                let trust = self.get_trust(&entry.agent_id);
                RoutingPriority {
                    agent_id: entry.agent_id.clone(),
                    trust_score: trust,
                    confidence: self.registry
                        .profiles
                        .get(&entry.agent_id)
                        .and_then(|p| p.contexts.get(&self.routing_context))
                        .map(|s| s.confidence)
                        .unwrap_or(0.1),
                    priority: trust * 10.0, // simple priority formula
                    estimated_latency_ms: if trust > 0.7 { 10 } else if trust > 0.3 { 50 } else { 200 },
                }
            })
            .collect()
    }

    /// Get agents sorted by trust (highest first).
    pub fn agents_by_trust(&self) -> Vec<(String, f64)> {
        let mut agents: Vec<(String, f64)> = self.routing_table
            .iter()
            .map(|(_, entry)| (entry.agent_id.clone(), entry.trust_score))
            .collect();
        agents.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        agents
    }

    /// Find agents with a specific capability, sorted by trust.
    pub fn find_by_capability(&self, capability: &str) -> Vec<(String, f64)> {
        let mut agents: Vec<(String, f64)> = self.routing_table
            .iter()
            .filter(|(_, entry)| entry.capabilities.contains(capability))
            .map(|(_, entry)| (entry.agent_id.clone(), entry.trust_score))
            .collect();
        agents.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        agents
    }

    /// Get the routing table size.
    pub fn table_size(&self) -> usize {
        self.routing_table.len()
    }

    /// Check if an agent is registered.
    pub fn is_registered(&self, agent_id: &str) -> bool {
        self.routing_table.contains_key(agent_id)
    }

    /// Remove an agent from the routing table.
    pub fn unregister(&mut self, agent_id: &str) {
        self.routing_table.remove(agent_id);
        self.trust_cache.remove(agent_id);
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Priority queue for trust-ordered message delivery.
#[derive(Clone, Debug)]
pub struct TrustPriorityQueue {
    heap: BinaryHeap<RoutingPriority>,
}

impl TrustPriorityQueue {
    pub fn new() -> Self {
        TrustPriorityQueue {
            heap: BinaryHeap::new(),
        }
    }

    /// Enqueue a message with its routing priority.
    pub fn enqueue(&mut self, priority: RoutingPriority) {
        self.heap.push(priority);
    }

    /// Dequeue the highest-priority message.
    pub fn dequeue(&mut self) -> Option<RoutingPriority> {
        self.heap.pop()
    }

    /// Peek at the highest-priority message without removing it.
    pub fn peek(&self) -> Option<&RoutingPriority> {
        self.heap.peek()
    }

    /// Number of items in the queue.
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

impl Default for TrustPriorityQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustScore;

    fn make_envelope(sender: &str, recipient: Option<&str>, kind: I2IMessageKind, trust: f64) -> I2IEnvelope {
        let mut ts = TrustScore::new("nav");
        ts.value = trust;
        ts.confidence = 0.8;
        I2IEnvelope::with_trust_score(sender, recipient, kind, vec![], &ts)
    }

    #[test]
    fn test_route_direct() {
        let registry = TrustRegistry::new();
        let mut router = TrustRouter::new(registry, "nav");
        let mut caps = HashSet::new();
        caps.insert("nav".to_string());
        router.register_agent("bob", caps, false);

        let env = make_envelope("alice", Some("bob"), I2IMessageKind::Request, 0.8);
        let decision = router.route(&env);
        assert_eq!(decision, RoutingDecision::Direct);
    }

    #[test]
    fn test_route_broadcast() {
        let registry = TrustRegistry::new();
        let router = TrustRouter::new(registry, "nav");
        let env = make_envelope("alice", None, I2IMessageKind::Broadcast, 0.8);
        let decision = router.route(&env);
        assert_eq!(decision, RoutingDecision::Broadcast);
    }

    #[test]
    fn test_route_drop_low_trust() {
        let registry = TrustRegistry::new();
        let mut router = TrustRouter::new(registry, "nav")
            .with_thresholds(0.7, 0.5);
        let mut caps = HashSet::new();
        caps.insert("nav".to_string());
        router.register_agent("bob", caps, false);

        let env = make_envelope("alice", Some("bob"), I2IMessageKind::Request, 0.1);
        let decision = router.route(&env);
        assert!(matches!(decision, RoutingDecision::Drop { .. }));
    }

    #[test]
    fn test_route_via_relay() {
        let registry = TrustRegistry::new();
        let mut router = TrustRouter::new(registry, "nav")
            .with_thresholds(0.7, 0.5);
        let mut caps = HashSet::new();
        caps.insert("nav".to_string());
        router.register_agent("bob", caps.clone(), false);

        // Register a relay
        let mut relay_caps = HashSet::new();
        relay_caps.insert("relay".to_string());
        router.register_agent("relay1", relay_caps, true);

        // Sender has trust between relay and direct threshold
        let env = make_envelope("alice", Some("bob"), I2IMessageKind::Request, 0.6);
        let decision = router.route(&env);
        assert_eq!(decision, RoutingDecision::ViaRelay { relay_agent: "relay1".to_string() });
    }

    #[test]
    fn test_route_no_recipient_in_table() {
        let registry = TrustRegistry::new();
        let router = TrustRouter::new(registry, "nav");
        let env = make_envelope("alice", Some("unknown"), I2IMessageKind::Request, 0.8);
        let decision = router.route(&env);
        assert!(matches!(decision, RoutingDecision::Drop { .. }));
    }

    #[test]
    fn test_agents_by_trust() {
        let registry = TrustRegistry::new();
        let mut router = TrustRouter::new(registry, "nav");
        router.register_agent("low", HashSet::new(), false);
        router.register_agent("high", HashSet::new(), false);
        router.register_agent("mid", HashSet::new(), false);

        // Manually set trust scores in routing table
        if let Some(entry) = router.routing_table.get_mut("low") {
            entry.trust_score = 0.2;
        }
        if let Some(entry) = router.routing_table.get_mut("high") {
            entry.trust_score = 0.9;
        }
        if let Some(entry) = router.routing_table.get_mut("mid") {
            entry.trust_score = 0.5;
        }

        let sorted = router.agents_by_trust();
        assert_eq!(sorted[0].1, 0.9);
        assert_eq!(sorted[2].1, 0.2);
    }

    #[test]
    fn test_find_by_capability() {
        let registry = TrustRegistry::new();
        let mut router = TrustRouter::new(registry, "nav");

        let mut caps1 = HashSet::new();
        caps1.insert("navigation".to_string());
        router.register_agent("nav1", caps1, false);

        let mut caps2 = HashSet::new();
        caps2.insert("navigation".to_string());
        caps2.insert("combat".to_string());
        router.register_agent("multi", caps2, false);

        let mut caps3 = HashSet::new();
        caps3.insert("medical".to_string());
        router.register_agent("medic", caps3, false);

        let nav_agents = router.find_by_capability("navigation");
        assert_eq!(nav_agents.len(), 2);
        let med_agents = router.find_by_capability("medical");
        assert_eq!(med_agents.len(), 1);
    }

    #[test]
    fn test_priority_queue() {
        let mut queue = TrustPriorityQueue::new();
        assert!(queue.is_empty());

        queue.enqueue(RoutingPriority {
            agent_id: "low".to_string(),
            trust_score: 0.2,
            confidence: 0.5,
            priority: 2.0,
            estimated_latency_ms: 200,
        });
        queue.enqueue(RoutingPriority {
            agent_id: "high".to_string(),
            trust_score: 0.9,
            confidence: 0.9,
            priority: 9.0,
            estimated_latency_ms: 10,
        });
        queue.enqueue(RoutingPriority {
            agent_id: "mid".to_string(),
            trust_score: 0.5,
            confidence: 0.6,
            priority: 5.0,
            estimated_latency_ms: 50,
        });

        assert_eq!(queue.len(), 3);

        let first = queue.dequeue().unwrap();
        assert_eq!(first.agent_id, "high");
        let second = queue.dequeue().unwrap();
        assert_eq!(second.agent_id, "mid");
        let third = queue.dequeue().unwrap();
        assert_eq!(third.agent_id, "low");
        assert!(queue.is_empty());
    }

    #[test]
    fn test_register_and_unregister() {
        let registry = TrustRegistry::new();
        let mut router = TrustRouter::new(registry, "nav");
        router.register_agent("agent1", HashSet::new(), false);
        assert!(router.is_registered("agent1"));
        assert_eq!(router.table_size(), 1);
        router.unregister("agent1");
        assert!(!router.is_registered("agent1"));
        assert_eq!(router.table_size(), 0);
    }

    #[test]
    fn test_route_queue_for_medium_trust() {
        let registry = TrustRegistry::new();
        let mut router = TrustRouter::new(registry, "nav")
            .with_thresholds(0.7, 0.5);
        let mut caps = HashSet::new();
        caps.insert("nav".to_string());
        router.register_agent("bob", caps, false);

        // No relay registered, sender below direct but above half relay
        let env = make_envelope("alice", Some("bob"), I2IMessageKind::Request, 0.3);
        let decision = router.route(&env);
        assert_eq!(decision, RoutingDecision::Queue);
    }
}
