/*!
# I2I Fleet Protocol Integration

Wires the trust engine into the iron-to-iron (I2I) fleet protocol.
Every I2I message carries trust attestation, is validated by trust
middleware, routed by trust-aware routing, and changes propagate
through the fleet.

## Module Structure

- **message**: Trust-aware message envelopes, attestations, wire formats
- **middleware**: Trust validation and enforcement middleware
- **routing**: Trust-aware message routing and priority queues
- **propagation**: Trust gossip and fleet-wide propagation engine
*/

pub mod message;
pub mod middleware;
pub mod routing;
pub mod propagation;

// Re-export key types at the i2i level for convenience
pub use message::{
    I2IEnvelope, I2IMessageKind, I2IProtocolHeader,
    MessageId, TrustAttestation, TrustAwareMessage, TrustSignature, WireTrustScore,
};
pub use middleware::{
    TrustMiddleware, TrustPolicy, TrustValidationResult, TrustRejectionReason,
    TrustFilter, BatchValidationResult,
};
pub use routing::{
    TrustRouter, RoutingDecision, RoutingPriority, TrustPriorityQueue,
};
pub use propagation::{
    TrustPropagator, TrustUpdate, TrustChangeDirection, TrustGossip,
    PropagationPolicy, create_gossip_envelopes,
};

/// End-to-end I2I trust pipeline: validate → route → propagate.
///
/// This struct ties together all I2I trust components into a single
/// coherent pipeline for processing fleet messages.
#[derive(Clone, Debug)]
pub struct I2ITrustPipeline {
    /// Trust validation middleware.
    middleware: TrustMiddleware,
    /// Trust-aware router.
    router: TrustRouter,
    /// Trust propagation engine.
    propagator: TrustPropagator,
}

impl I2ITrustPipeline {
    /// Create a new pipeline with a shared trust registry.
    pub fn new(registry: crate::TrustRegistry, routing_context: &str) -> Self {
        let middleware = TrustMiddleware::new(registry.clone());
        let router = TrustRouter::new(registry.clone(), routing_context);
        let propagator = TrustPropagator::new(registry);

        I2ITrustPipeline {
            middleware,
            router,
            propagator,
        }
    }

    /// Create a pipeline with custom components.
    pub fn with_components(
        middleware: TrustMiddleware,
        router: TrustRouter,
        propagator: TrustPropagator,
    ) -> Self {
        I2ITrustPipeline {
            middleware,
            router,
            propagator,
        }
    }

    /// Process an I2I envelope through the full trust pipeline.
    ///
    /// Returns the routing decision and validation result.
    pub fn process(&mut self, envelope: &I2IEnvelope) -> PipelineResult {
        // Step 1: Validate trust
        let validation = self.middleware.validate(envelope);

        match &validation {
            TrustValidationResult::Accept => {
                // Step 2: Route based on trust
                let routing = self.router.route(envelope);

                match &routing {
                    RoutingDecision::Direct | RoutingDecision::Broadcast => {
                        // Record positive interaction
                        self.middleware.registry_mut().interact(
                            "i2i-pipeline",
                            &envelope.sender,
                            &envelope.trust_context,
                            true,
                        );
                    }
                    RoutingDecision::Drop { .. } => {
                        // Record negative interaction
                        self.middleware.registry_mut().interact(
                            "i2i-pipeline",
                            &envelope.sender,
                            &envelope.trust_context,
                            false,
                        );
                    }
                    _ => {}
                }

                let should_deliver = matches!(
                    routing,
                    RoutingDecision::Direct | RoutingDecision::Broadcast | RoutingDecision::ViaRelay { .. }
                );

                PipelineResult {
                    validation: validation.clone(),
                    routing,
                    should_deliver,
                }
            }
            TrustValidationResult::Reject(reason) => {
                // Record negative interaction for rejected messages
                self.middleware.registry_mut().interact(
                    "i2i-pipeline",
                    &envelope.sender,
                    &envelope.trust_context,
                    false,
                );

                let reason_str = format!("trust rejected: {}", reason);
                PipelineResult {
                    validation: validation.clone(),
                    routing: RoutingDecision::Drop {
                        reason: reason_str,
                    },
                    should_deliver: false,
                }
            }
            TrustValidationResult::Quarantine { .. } => {
                PipelineResult {
                    validation: validation.clone(),
                    routing: RoutingDecision::Queue,
                    should_deliver: false,
                }
            }
        }
    }

    /// Process a batch of envelopes and return results.
    pub fn process_batch(&mut self, envelopes: Vec<I2IEnvelope>) -> Vec<PipelineResult> {
        envelopes.iter().map(|e| self.process(e)).collect()
    }

    /// Propagate any pending trust updates.
    pub fn propagate_trust(&mut self, sender: &str) -> Vec<I2IEnvelope> {
        create_gossip_envelopes(&mut self.propagator, sender)
    }

    /// Record a trust change and queue for propagation.
    pub fn record_trust_change(
        &mut self,
        agent_id: &str,
        context: &str,
        previous_trust: f64,
        new_trust: f64,
        observer: &str,
    ) {
        self.propagator.record_change(agent_id, context, previous_trust, new_trust, observer);
    }

    /// Access the middleware.
    pub fn middleware(&self) -> &TrustMiddleware {
        &self.middleware
    }

    /// Access the middleware mutably.
    pub fn middleware_mut(&mut self) -> &mut TrustMiddleware {
        &mut self.middleware
    }

    /// Access the router.
    pub fn router(&self) -> &TrustRouter {
        &self.router
    }

    /// Access the router mutably.
    pub fn router_mut(&mut self) -> &mut TrustRouter {
        &mut self.router
    }

    /// Access the propagator.
    pub fn propagator(&self) -> &TrustPropagator {
        &self.propagator
    }

    /// Access the propagator mutably.
    pub fn propagator_mut(&mut self) -> &mut TrustPropagator {
        &mut self.propagator
    }
}

/// Result of processing a message through the trust pipeline.
#[derive(Clone, Debug)]
pub struct PipelineResult {
    /// Trust validation outcome.
    pub validation: TrustValidationResult,
    /// Routing decision.
    pub routing: RoutingDecision,
    /// Whether the message should be delivered.
    pub should_deliver: bool,
}

/// Message processing statistics for the I2I trust pipeline.
#[derive(Clone, Debug, Default)]
pub struct PipelineStats {
    pub total_processed: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub quarantined: u64,
    pub delivered: u64,
    pub dropped: u64,
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::{TrustRegistry, TrustScore};

    fn make_envelope(sender: &str, recipient: Option<&str>, trust: f64) -> I2IEnvelope {
        let mut ts = TrustScore::new("nav");
        ts.value = trust;
        ts.confidence = 0.8;
        I2IEnvelope::with_trust_score(sender, recipient, I2IMessageKind::Request, vec![], &ts)
    }

    #[test]
    fn test_pipeline_accept_and_route_direct() {
        let registry = TrustRegistry::new();
        let mut pipeline = I2ITrustPipeline::new(registry, "nav");

        let mut caps = std::collections::HashSet::new();
        caps.insert("nav".to_string());
        pipeline.router_mut().register_agent("bob", caps, false);

        let env = make_envelope("alice", Some("bob"), 0.8);
        let result = pipeline.process(&env);
        assert!(matches!(result.validation, TrustValidationResult::Accept));
        assert_eq!(result.routing, RoutingDecision::Direct);
        assert!(result.should_deliver);
    }

    #[test]
    fn test_pipeline_reject_low_trust() {
        let registry = TrustRegistry::new();
        let mut pipeline = I2ITrustPipeline::new(registry, "nav");

        let env = make_envelope("alice", Some("bob"), 0.05);
        let result = pipeline.process(&env);
        assert!(matches!(result.validation, TrustValidationResult::Reject(_)));
        assert!(!result.should_deliver);
    }

    #[test]
    fn test_pipeline_broadcast() {
        let registry = TrustRegistry::new();
        let mut pipeline = I2ITrustPipeline::new(registry, "nav");

        let env = make_envelope("alice", None, 0.8);
        let result = pipeline.process(&env);
        assert!(matches!(result.validation, TrustValidationResult::Accept));
        assert_eq!(result.routing, RoutingDecision::Broadcast);
        assert!(result.should_deliver);
    }

    #[test]
    fn test_pipeline_records_interaction() {
        let registry = TrustRegistry::new();
        let mut pipeline = I2ITrustPipeline::new(registry, "nav");

        // Register recipient so routing can find it
        let mut caps = std::collections::HashSet::new();
        caps.insert("nav".to_string());
        pipeline.router_mut().register_agent("bob", caps, false);

        let env = make_envelope("alice", Some("bob"), 0.8);
        pipeline.process(&env);

        // The middleware records trust for "i2i-pipeline" about the sender
        let trust = pipeline.middleware().registry()
            .trust_level("i2i-pipeline", "alice", "nav");
        assert!(trust > 0.5); // positive interaction recorded
    }

    #[test]
    fn test_pipeline_records_negative_on_reject() {
        let registry = TrustRegistry::new();
        let mut pipeline = I2ITrustPipeline::new(registry, "nav");

        let env = make_envelope("bad_actor", Some("bob"), 0.05);
        pipeline.process(&env);

        let trust = pipeline.middleware().registry()
            .trust_level("i2i-pipeline", "bad_actor", "nav");
        assert!(trust < 0.5); // negative interaction recorded
    }

    #[test]
    fn test_pipeline_batch() {
        let registry = TrustRegistry::new();
        let mut pipeline = I2ITrustPipeline::new(registry, "nav");

        // Register bob so direct routing works
        let mut caps = std::collections::HashSet::new();
        caps.insert("nav".to_string());
        pipeline.router_mut().register_agent("bob", caps, false);

        let envelopes = vec![
            make_envelope("alice", Some("bob"), 0.8),
            make_envelope("mallory", Some("bob"), 0.05),
            make_envelope("carol", None, 0.6),
        ];

        let results = pipeline.process_batch(envelopes);
        assert_eq!(results.len(), 3);
        assert!(results[0].should_deliver); // alice: high trust, direct
        assert!(!results[1].should_deliver); // mallory: rejected
        assert!(results[2].should_deliver); // carol: broadcast
    }

    #[test]
    fn test_pipeline_trust_propagation() {
        let registry = TrustRegistry::new();
        let mut pipeline = I2ITrustPipeline::new(registry, "nav");
        pipeline.propagator_mut().add_neighbor("alice", "bob");

        pipeline.record_trust_change("alice", "nav", 0.5, 0.8, "observer");

        let gossips = pipeline.propagate_trust("sender");
        assert_eq!(gossips.len(), 1);
        assert_eq!(gossips[0].kind, I2IMessageKind::Gossip);
    }

    #[test]
    fn test_full_roundtrip_envelope() {
        // Create, serialize, deserialize, process
        let mut ts = TrustScore::new("nav");
        ts.reward(1.0);
        ts.reward(1.0);

        let envelope = I2IEnvelope::with_trust_score(
            "alice", Some("bob"), I2IMessageKind::Request,
            b"hello fleet".to_vec(), &ts,
        );

        let bytes = envelope.to_json_bytes().unwrap();
        let decoded = I2IEnvelope::from_json_bytes(&bytes).unwrap();

        let registry = TrustRegistry::new();
        let mut pipeline = I2ITrustPipeline::new(registry, "nav");

        // Register bob so routing can find it
        let mut caps = std::collections::HashSet::new();
        caps.insert("nav".to_string());
        pipeline.router_mut().register_agent("bob", caps, false);

        let result = pipeline.process(&decoded);
        assert!(result.should_deliver);
    }
}
