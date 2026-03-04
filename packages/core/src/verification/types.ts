export type VerificationStatus = "ok" | "invalid" | "inconclusive";

export type VerificationViolationCode =
  | "MALFORMED_EVENT"
  | "POLICY_ID_MISSING"
  | "POLICY_ID_MISMATCH"
  | "MIXED_POLICY_ID"
  | "NON_MONOTONIC_TIMESTAMP"
  | "HASH_CHAIN_INVALID"
  | "NO_STATE_ANCHOR"
  | "SNAPSHOT_CORRUPT"
  | "ENVELOPE_MALFORMED";

export type VerificationViolation = {
  code: VerificationViolationCode;
  message?: string;
  index?: number;
};

export type VerificationResult = {
  ok: boolean;
  status: VerificationStatus;
  violations: VerificationViolation[];

  policyId?: string;
  stateHash?: string;
  auditHeadHash?: string;
};

export type VerifyAuditOptions = {
  expectedPolicyId?: string;
  mode?: "strict" | "best-effort";
  requireStateAnchors?: boolean;
};

export type VerifyEnvelopeOptions = {
  expectedPolicyId?: string;
  mode?: "strict" | "best-effort";
};
