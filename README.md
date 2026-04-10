# cuda-trust

**Multi-context trust with exponential decay and Bayesian fusion.**

> Trust is earned slowly and lost quickly.
> This asymmetry is the foundation of fleet security.

## How It Works

Trust in the fleet is not binary. It's a continuously-updated value per context:

- **Decay**: Trust decreases exponentially with half-life
- **Growth**: Trust increases slowly (1/10 the decay rate)
- **Fusion**: Multiple trust signals combine via harmonic mean
- **Gossip**: Agents share trust assessments with neighbors

### Trust Contexts

An agent can trust "navigator" for pathfinding but not for cooking. Trust is per-capability, not per-agent.

## Biological Parallel

Serotonin IS trust. Sustained social bonds build serotonin receptors. Betrayal down-regulates them. The slow growth / fast decay mirrors real neurochemistry.

## Ecosystem Integration

- `cuda-a2a` - TrustScore used for message routing
- `cuda-social` - Reputation is trust aggregated across agents
- `cuda-did` - DID attestations build trust
- `cuda-compliance` - Trust gates policy enforcement
- `cuda-confidence` - Same mathematical structure as confidence

## See Also

- [cuda-a2a](https://github.com/Lucineer/cuda-a2a) - Trust in message routing
- [cuda-social](https://github.com/Lucineer/cuda-social) - Reputation system
- [cuda-did](https://github.com/Lucineer/cuda-did) - Identity verification
- [cuda-compliance](https://github.com/Lucineer/cuda-compliance) - Policy enforcement

## License

MIT OR Apache-2.0