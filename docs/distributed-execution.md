# Distributed production execution

Phase 12 defines a provider-neutral distributed execution boundary without claiming that
a broker or multi-node worker deployment exists in this repository.

```text
FastAPI -> application service -> SimulationDispatcher
                                      |
                                      v
                              BrokerTransport port
                                      |
                              external broker/worker
                                      |
                                      v
                              SimulationWorker.run_job
                                      |
                         server-grade OperationalStore
```

`BrokerSimulationDispatcher` publishes a strict `SimulationJobV1` through an injected
`BrokerTransport`. The adapter can be implemented for Redis Streams, RabbitMQ, Kafka,
SQS, or another broker without changing application or domain code. The repository does
not connect to any of them.

An external worker receives the serialized job, validates it, and invokes
`SimulationWorker.run_serialized()` or `run_job()`. `BrokerJobConsumer` and
`BrokerJobDelivery` define receive, acknowledge, retry, and dead-letter settlement.
Deployments own the concrete consumer loop, connection lifecycle, and broker security.

## Delivery and ownership

Broker delivery is at-least-once. The stable message ID is derived from run, workflow,
contract version, and attempt, and is used as the broker deduplication key. Duplicate
delivery remains safe even without broker deduplication because the operational store
allows at most one active lease and fencing generation per run.

This is not exactly-once message delivery. It is idempotent logical execution with an
atomic immutable result publication boundary.

## Deployment modes

- Development: `LocalSimulationDispatcher`, in-process queue, SQLite, one process.
- Single node: local dispatcher plus durable SQLite recovery; not multi-replica safe.
- Production architecture: distributed dispatcher, external consumers, server-grade
  store, external secrets, durable audit, and external telemetry.

Production composition rejects process-local dispatchers and single-node stores.
