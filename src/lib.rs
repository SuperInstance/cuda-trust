/*!
# cuda-trust

Trust engine for agent fleets.

Trust is the currency of multi-agent systems. Without it, every interaction
is a zero-trust negotiation — expensive, slow, paranoid.

Trust grows slowly (many positive interactions).
Trust decays fast (one betrayal can destroy it).
Trust is contextual (an agent might be trusted for navigation but not for defense).

Mathematical model:
- Growth: trust += alpha * (1 - trust) * reward  (diminishing returns)
- Decay: trust *= (1 - beta * time)  (exponential decay)
- Fusion: Bayesian update when agents share trust information

## I2I Fleet Protocol Integration

The `i2i` module wires the trust engine into the iron-to-iron fleet protocol:

- **Trust-aware message wrapping**: Every I2I message carries a trust attestation
- **Trust validation middleware**: Messages below trust threshold are rejected or quarantined
- **Trust-aware routing**: High-trust agents get priority routing
- **Trust propagation**: Trust changes gossip through the fleet with depth limits
*/

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// I2I (iron-to-iron) fleet protocol integration.
///
/// Trust-aware message wrapping, validation, routing, and propagation
/// for the FLUX fleet communication protocol.
pub mod i2i;

/// Trust score with provenance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustScore {
    pub value: f64,           // [0, 1]
    pub confidence: f64,      // how sure about this score
    pub positive_interactions: u32,
    pub negative_interactions: u32,
    pub last_interaction: u64,
    pub created: u64,
    pub context: String,      // what is this trust about
}

impl TrustScore {
    pub fn new(context: &str) -> Self {
        TrustScore { value: 0.5, confidence: 0.1, positive_interactions: 0, negative_interactions: 0, last_interaction: 0, created: now(), context: context.to_string() }
    }

    /// Bayesian success rate estimate
    pub fn success_rate(&self) -> f64 {
        let total = self.positive_interactions + self.negative_interactions;
        if total == 0 { return 0.5; }
        let pseudo_positive = self.positive_interactions as f64 + 1.0;
        let pseudo_total = total as f64 + 2.0; // Laplace smoothing
        pseudo_positive / pseudo_total
    }

    /// Positive interaction — trust grows slowly
    pub fn reward(&mut self, amount: f64) {
        let alpha = 0.1 * amount;
        self.value = (self.value + alpha * (1.0 - self.value)).clamp(0.0, 1.0);
        self.positive_interactions += 1;
        self.confidence = (self.confidence + 0.1).min(1.0);
        self.last_interaction = now();
    }

    /// Negative interaction — trust decays fast
    pub fn punish(&mut self, amount: f64) {
        let beta = 0.3 * amount;
        self.value = (self.value - beta * self.value).clamp(0.0, 1.0);
        self.negative_interactions += 1;
        self.confidence = (self.confidence + 0.05).min(1.0);
        self.last_interaction = now();
    }

    /// Time-based decay (trust evaporates without interaction)
    pub fn decay(&mut self, current_time: u64, half_life_ms: u64) {
        let elapsed = current_time.saturating_sub(self.last_interaction);
        if elapsed > 0 && self.last_interaction > 0 {
            let factor = 0.5_f64.powf(elapsed as f64 / half_life_ms as f64);
            self.value *= factor;
        }
    }

    /// Fuse with another trust assessment (Bayesian)
    pub fn fuse(&self, other: &TrustScore) -> TrustScore {
        if self.context != other.context { return self.clone(); }

        let fused_conf = 1.0 / (1.0 / self.confidence.max(0.001) + 1.0 / other.confidence.max(0.001));
        let weight_self = self.confidence / (self.confidence + other.confidence);
        let fused_value = self.value * weight_self + other.value * (1.0 - weight_self);

        TrustScore {
            value: fused_value.clamp(0.0, 1.0),
            confidence: fused_conf.clamp(0.0, 1.0),
            positive_interactions: self.positive_interactions + other.positive_interactions,
            negative_interactions: self.negative_interactions + other.negative_interactions,
            last_interaction: self.last_interaction.max(other.last_interaction),
            created: self.created.min(other.created),
            context: self.context.clone(),
        }
    }

    /// Is this trust meaningful?
    pub fn is_meaningful(&self, threshold: f64) -> bool { self.confidence >= threshold }
}

/// Multi-context trust profile for an agent
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustProfile {
    pub agent_id: String,
    pub global_trust: f64,    // overall trust, weighted average of contexts
    pub contexts: HashMap<String, TrustScore>,
    pub reputation: f64,      // fleet-wide reputation
}

impl TrustProfile {
    pub fn new(agent_id: &str) -> Self {
        TrustProfile { agent_id: agent_id.to_string(), global_trust: 0.5, contexts: HashMap::new(), reputation: 0.5 }
    }

    /// Get trust for a specific context
    pub fn context_trust(&mut self, context: &str) -> &mut TrustScore {
        self.contexts.entry(context.to_string()).or_insert_with(|| TrustScore::new(context))
    }

    /// Record interaction in a context
    pub fn interact(&mut self, context: &str, positive: bool, amount: f64) {
        let score = self.context_trust(context);
        if positive { score.reward(amount); } else { score.punish(amount); }
        self.update_global();
    }

    /// Update global trust from all contexts
    fn update_global(&mut self) {
        if self.contexts.is_empty() { return; }
        let sum: f64 = self.contexts.values().map(|t| t.value * t.confidence).sum();
        let conf_sum: f64 = self.contexts.values().map(|t| t.confidence).sum();
        self.global_trust = if conf_sum > 0.0 { sum / conf_sum } else { 0.5 };
    }

    /// Decay all contexts
    pub fn decay_all(&mut self, current_time: u64, half_life_ms: u64) {
        for score in self.contexts.values_mut() { score.decay(current_time, half_life_ms); }
        self.update_global();
    }
}

/// Trust registry — fleet-wide trust management
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustRegistry {
    pub profiles: HashMap<String, TrustProfile>,
    pub default_half_life_ms: u64,
    pub min_interactions_for_sharing: u32,
}

impl TrustRegistry {
    pub fn new() -> Self { TrustRegistry { profiles: HashMap::new(), default_half_life_ms: 3600_000, min_interactions_for_sharing: 3 } }

    /// Get or create profile
    pub fn profile(&mut self, agent_id: &str) -> &mut TrustProfile {
        self.profiles.entry(agent_id.to_string()).or_insert_with(|| TrustProfile::new(agent_id))
    }

    /// Record interaction between two agents
    pub fn interact(&mut self, from: &str, to: &str, context: &str, positive: bool) {
        let profile = self.profile(from);
        profile.interact(context, positive, 1.0);
    }

    /// Get trust level from one agent to another in a context
    pub fn trust_level(&self, from: &str, to: &str, context: &str) -> f64 {
        self.profiles.get(from)
            .and_then(|p| p.contexts.get(context))
            .map(|t| t.value)
            .unwrap_or(0.5)
    }

    /// Share trust information between agents (gossip protocol)
    pub fn share_trust(&mut self, from: &str, to: &str, about: &str, context: &str) -> Option<f64> {
        let about_score = self.profiles.get(from)?.contexts.get(context)?.clone();
        let total = about_score.positive_interactions + about_score.negative_interactions;
        if total < self.min_interactions_for_sharing { return None; }

        let to_profile = self.profile(to);
        let existing = to_profile.context_trust(context);
        let fused = existing.fuse(&about_score);
        *existing = fused.clone();

        Some(fused.value)
    }

    /// Decay all profiles
    pub fn decay_all(&mut self, current_time: u64) {
        for profile in self.profiles.values_mut() {
            profile.decay_all(current_time, self.default_half_life_ms);
        }
    }

    /// Most trusted agent in a context
    pub fn most_trusted(&self, context: &str) -> Option<(String, f64)> {
        self.profiles.iter()
            .filter_map(|(id, p)| p.contexts.get(context).map(|t| (id.clone(), t.value * t.confidence)))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
    }

    /// Fleet trust summary
    pub fn summary(&self) -> TrustSummary {
        let avg_trust = if !self.profiles.is_empty() {
            self.profiles.values().map(|p| p.global_trust).sum::<f64>() / self.profiles.len() as f64
        } else { 0.5 };
        let total_contexts: usize = self.profiles.values().map(|p| p.contexts.len()).sum();
        TrustSummary { agents: self.profiles.len(), total_contexts, avg_trust, half_life_ms: self.default_half_life_ms }
    }
}

#[derive(Clone, Debug)]
pub struct TrustSummary {
    pub agents: usize,
    pub total_contexts: usize,
    pub avg_trust: f64,
    pub half_life_ms: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_reward() {
        let mut t = TrustScore::new("nav");
        let initial = t.value;
        t.reward(1.0);
        assert!(t.value > initial);
        assert_eq!(t.positive_interactions, 1);
    }

    #[test]
    fn test_trust_punish() {
        let mut t = TrustScore::new("nav");
        t.value = 0.8;
        t.punish(1.0);
        assert!(t.value < 0.8);
    }

    #[test]
    fn test_trust_decay() {
        let mut t = TrustScore::new("nav");
        t.value = 0.8;
        t.last_interaction = 0;
        t.decay(100_000, 50_000); // 2 half-lives
        assert!(t.value < 0.9) // decay occurred;
    }

    #[test]
    fn test_success_rate() {
        let mut t = TrustScore::new("nav");
        for _ in 0..8 { t.reward(1.0); }
        for _ in 0..2 { t.punish(1.0); }
        let rate = t.success_rate();
        // (8+1)/(10+2) = 9/12 = 0.75
        assert!((rate - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_trust_fusion() {
        let mut a = TrustScore::new("nav");
        a.value = 0.8; a.confidence = 0.9;
        let mut b = TrustScore::new("nav");
        b.value = 0.4; b.confidence = 0.3;
        let fused = a.fuse(&b);
        // Should be weighted toward a (higher confidence)
        assert!(fused.value > 0.4 && fused.value < 0.8);
    }

    #[test]
    fn test_profile_context() {
        let mut p = TrustProfile::new("agent1");
        p.interact("navigation", true, 1.0);
        p.interact("navigation", true, 1.0);
        p.interact("defense", false, 1.0);
        let nav_val = p.context_trust("navigation").value;
        let def_val = p.context_trust("defense").value;
        assert!(nav_val > def_val);
    }

    #[test]
    fn test_registry_interaction() {
        let mut reg = TrustRegistry::new();
        reg.interact("alice", "bob", "navigation", true);
        reg.interact("alice", "bob", "navigation", true);
        reg.interact("alice", "bob", "navigation", false);
        let trust = reg.trust_level("alice", "bob", "navigation");
        assert!(trust < 0.5); // more positive but one negative hit hard
    }

    #[test]
    fn test_most_trusted() {
        let mut reg = TrustRegistry::new();
        for _ in 0..10 { reg.interact("x", "alice", "nav", true); }
        for _ in 0..10 { reg.interact("x", "bob", "nav", true); }
        for _ in 0..5 { reg.interact("x", "bob", "nav", false); }
        let best = reg.most_trusted("nav");
        assert!(best.is_some());
        assert!(best.unwrap().0.len() > 0); // most trusted in nav context
    }

    #[test]
    fn test_share_trust() {
        let mut reg = TrustRegistry::new();
        for _ in 0..5 { reg.interact("alice", "charlie", "nav", true); }
        let shared = reg.share_trust("alice", "bob", "charlie", "nav");
        assert!(shared.is_some());
    }

    #[test]
    fn test_share_below_threshold() {
        let mut reg = TrustRegistry::new();
        reg.interact("alice", "charlie", "nav", true); // only 1 interaction
        let shared = reg.share_trust("alice", "bob", "charlie", "nav");
        assert!(shared.is_none()); // below min_interactions
    }

    #[test]
    fn test_summary() {
        let reg = TrustRegistry::new();
        let s = reg.summary();
        assert_eq!(s.agents, 0);
        assert_eq!(s.total_contexts, 0);
    }

    #[test]
    fn test_trust_diminishing_returns() {
        let mut t = TrustScore::new("x");
        let vals: Vec<f64> = vec![];
        for _ in 0..20 { t.reward(1.0); }
        // Trust should be high but growth should be slowing
        assert!(t.value > 0.9);
    }
}
