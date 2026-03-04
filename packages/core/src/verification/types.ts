export type VerificationStatus = "ok" | "invalid" | "inconclusive";

export type AuditVerificationMode = "strict" | "best-effort";

export type VerificationResult = {
  status: VerificationStatus;
  violations: string[];
};

export type SnapshotVerificationResult = VerificationResult & {
  stateHash?: string;
  policyId?: string;
  formatVersion?: number;
};

export type VerifyAuditOptions = {
  expectedPolicyId?: string;
  mode?: AuditVerificationMode;
  requireStateAnchors?: boolean;
};

export type AuditVerificationViolation =
  | { code: "MALFORMED_EVENT"; message: string; index?: number }
  | { code: "POLICY_ID_MISSING"; message: string; index?: number }
  | { code: "POLICY_ID_MISMATCH"; message: string; expected: string; got: string; index?: number }
  | { code: "MIXED_POLICY_ID"; message: string }
  | { code: "NON_MONOTONIC_TIMESTAMP"; message: string; prev: number; next: number; index: number }
  | { code: "HASH_CHAIN_INVALID"; message: string }
  | { code: "NO_STATE_ANCHOR"; message: string };

export type AuditVerificationResult = {
  ok: boolean;
  status: VerificationStatus;
  policyId?: string;
  auditHeadHash?: string;
  violations: AuditVerificationViolation[];
};
