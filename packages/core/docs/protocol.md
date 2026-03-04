# OxDeAI Verification Protocol

## Snapshot

Deterministic binary encoding of policy state.

Properties:

- canonical
- stable hashing
- portable

## Audit Events

Hash-chained event sequence describing policy execution history.

Rules:

- monotonic timestamps
- policyId consistency
- deterministic hashing

## Verification Envelope

Format: `VerificationEnvelopeV1`

```json
{
  "formatVersion": 1,
  "snapshot": "<base64>",
  "events": []
}
```

## Stateless Verifiers

- `verifySnapshot`
- `verifyAuditEvents`
- `verifyEnvelope`

All return `VerificationResult`.
