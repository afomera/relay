# Helm chart (stub)

An actual chart lives here once we've settled on:

- Stateful vs stateless: `relayd` keeps in-memory tunnel state per pod, so
  horizontal scaling needs either sticky routing (session affinity on the
  QUIC/UDP side is non-trivial) or a shared registry (Redis? gossip?). For now
  the single-replica deploy is the only supported shape.
- TLS: cert-manager integration is the obvious direction; the baked-in ACME
  client would become redundant. Self-host users who already run cert-manager
  should be able to mount certs from a Kubernetes Secret and disable the
  internal issuer.
- Port handling: HostPort for :443 UDP + :443 TCP + :80 is easiest; LoadBalancer
  with UDP pass-through is cloud-dependent.

Contributions welcome — until the chart ships, use `infra/docker/`.
