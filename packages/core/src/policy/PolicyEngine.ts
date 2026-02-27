import type { Intent } from "../types/intent.js";
import type { State } from "../types/state.js";
import type { Authorization } from "../types/authorization.js";
import type { ReasonCode, PolicyResult } from "../types/policy.js";

import { sha256HexFromJson } from "../crypto/hashes.js";
import { engineSignHmac } from "../crypto/sign.js";
import { engineVerifyHmac } from "../crypto/verify.js";

import { HashChainedLog } from "../audit/HashChainedLog.js";
import { KillSwitchModule } from "./modules/KillSwitchModule.js";
import { AllowlistModule } from "./modules/AllowlistModule.js";
import { BudgetModule } from "./modules/BudgetModule.js";
import { VelocityModule } from "./modules/VelocityModule.js";

import { ReplayModule } from "./modules/ReplayModule.js";
import { ConcurrencyModule } from "./modules/ConcurrencyModule.js";
import { RecursionDepthModule } from "./modules/RecursionDepthModule.js";

export type EngineEvalOptions = {
  mode?: "fail-fast" | "collect-all";
};

export type EvaluateOutput =
  | { decision: "ALLOW"; reasons: []; authorization: Authorization }
  | { decision: "DENY"; reasons: ReasonCode[] };

export type EngineOptions = {
  policy_version: string;
  engine_secret: string;
  authorization_ttl_seconds: number;
  deny_mode?: "collect-all" | "fail-fast";
};

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return isObject(v) && !Array.isArray(v);
}

function mergeInto(target: Record<string, unknown>, source: Record<string, unknown>): void {
  for (const key of Object.keys(source)) {
    const src = source[key];
    const dst = target[key];
    if (isPlainObject(src) && isPlainObject(dst)) {
      mergeInto(dst, src);
      continue;
    }
    target[key] = src;
  }
}

function deepMerge<T>(base: T, patch: Partial<T>): T {
  if (!isPlainObject(base) || !isPlainObject(patch)) return (patch as T) ?? base;

  const out: Record<string, unknown> = { ...(base as any) };
  mergeInto(out, patch as any);
  return out as T;
}

const MODULES = [KillSwitchModule, AllowlistModule, BudgetModule, VelocityModule] as const;

export class PolicyEngine {
  private readonly opts: EngineOptions;
  public readonly audit: HashChainedLog = new HashChainedLog();

  constructor(opts: EngineOptions) {
    this.opts = opts;
  }

  /**
   * validateState(): explicit runtime validation for fail-closed semantics.
   * Goal: structural corruption should return STATE_INVALID (not INTERNAL_ERROR).
   * Note: per-agent configuration is validated for the current intent.agent_id only.
   */
  private validateStateForIntent(state: unknown, intent: Intent): { ok: true } | { ok: false; reason: ReasonCode } {
    if (!isObject(state)) return { ok: false, reason: "STATE_INVALID" };

    // policy_version check is handled separately to keep reason specific
    if (!("policy_version" in state) || typeof (state as any).policy_version !== "string") {
      return { ok: false, reason: "STATE_INVALID" };
    }


    // Required top-level keys
    const requiredTop = [
      "period_id",
      "kill_switch",
      "allowlists",
      "budget",
      "max_amount_per_action",
      "velocity",
      "replay",
      "concurrency",
      "recursion"
    ];
    for (const k of requiredTop) {
      if (!(k in state)) return { ok: false, reason: "STATE_INVALID" };
    }

    const ks = (state as any).kill_switch;
    if (!isObject(ks) || typeof ks.global !== "boolean" || !isObject(ks.agents)) {
      return { ok: false, reason: "STATE_INVALID" };
    }

    const al = (state as any).allowlists;
    if (!isObject(al)) return { ok: false, reason: "STATE_INVALID" };

    const budget = (state as any).budget;
    if (!isObject(budget) || !isObject(budget.budget_limit) || !isObject(budget.spent_in_period)) {
      return { ok: false, reason: "STATE_INVALID" };
    }

    const caps = (state as any).max_amount_per_action;
    if (!isObject(caps)) return { ok: false, reason: "STATE_INVALID" };

    const vel = (state as any).velocity;
    if (!isObject(vel) || !isObject(vel.config) || !isObject(vel.counters)) return { ok: false, reason: "STATE_INVALID" };
    if (typeof (vel.config as any).window_seconds !== "number" || typeof (vel.config as any).max_actions !== "number") {
      return { ok: false, reason: "STATE_INVALID" };
    }

    const rp = (state as any).replay;
    if (!isObject(rp) || typeof rp.window_seconds !== "number" || typeof rp.max_nonces_per_agent !== "number" || !isObject(rp.nonces)) {
      return { ok: false, reason: "STATE_INVALID" };
    }

    const cc = (state as any).concurrency;
    if (!isObject(cc) || !isObject(cc.max_concurrent) || !isObject(cc.active) || !isObject(cc.active_auths)) {
      return { ok: false, reason: "STATE_INVALID" };
    }

    const rc = (state as any).recursion;
    if (!isObject(rc) || !isObject(rc.max_depth)) return { ok: false, reason: "STATE_INVALID" };

    // Per-agent minimal config for this intent
    const agent = intent.agent_id;
    if (budget.budget_limit[agent] === undefined) return { ok: false, reason: "STATE_INVALID" };
    if (caps[agent] === undefined) return { ok: false, reason: "STATE_INVALID" };
    if (cc.max_concurrent[agent] === undefined) return { ok: false, reason: "STATE_INVALID" };
    if (rc.max_depth[agent] === undefined) return { ok: false, reason: "STATE_INVALID" };

    return { ok: true };

    
  }

  private validateIntent(intent: Intent): { ok: true } | { ok: false; reason: ReasonCode } {
    if (intent.type === "RELEASE" && !intent.authorization_id) {
      return { ok: false, reason: "STATE_INVALID" };
    }
    return { ok: true };
  }

  evaluate(intent: Intent, state: State): EvaluateOutput {
    const out = this.evaluatePure(intent, state, { mode: "fail-fast" });

    if (out.decision === "DENY") return out;

    Object.assign(state, out.nextState);

    return { decision: "ALLOW", reasons: [], authorization: out.authorization };
  }

  verifyAuthorization(
    intent: Intent,
    authorization: Authorization,
    state: State,
    now?: number
  ): { valid: boolean; reason?: ReasonCode } {
    try {
      const t = now ?? Math.floor(Date.now() / 1000);

      const intent_hash = sha256HexFromJson(intent);
      if (intent_hash !== authorization.intent_hash) return { valid: false, reason: "AUTH_INTENT_MISMATCH" };
      if (t > authorization.expires_at) return { valid: false, reason: "AUTH_EXPIRED" };
      if (state.policy_version !== authorization.policy_version) return { valid: false, reason: "POLICY_VERSION_MISMATCH" };

      const authPayload = {
        intent_hash: authorization.intent_hash,
        policy_version: authorization.policy_version,
        state_snapshot_hash: authorization.state_snapshot_hash,
        decision: "ALLOW" as const,
        expires_at: authorization.expires_at
      };

      const ok = engineVerifyHmac(authPayload, authorization.engine_signature, this.opts.engine_secret);
      if (!ok) return { valid: false, reason: "AUTH_SIGNATURE_INVALID" };

      return { valid: true };
    } catch {
      return { valid: false, reason: "INTERNAL_ERROR" };
    }
  }

  evaluatePure(intent: Intent, state: State, opts?: EngineEvalOptions):
    | { decision: "ALLOW"; reasons: []; authorization: Authorization; nextState: State }
    | { decision: "DENY"; reasons: ReasonCode[] } {

    const mode = opts?.mode ?? "fail-fast";

    const iv = this.validateIntent(intent);
    if (!iv.ok) return { decision: "DENY", reasons: [iv.reason] };

    // Fail-closed + explicit runtime validation
    const v = this.validateStateForIntent(state as unknown, intent);
    if (!v.ok) return { decision: "DENY", reasons: [v.reason] };

    if (state.policy_version !== this.opts.policy_version) {
      return { decision: "DENY", reasons: ["POLICY_VERSION_MISMATCH"] };
    }

    try {
      const intent_hash = sha256HexFromJson(intent);
      this.audit.append({
        type: "INTENT_RECEIVED",
        intent_hash,
        agent_id: intent.agent_id,
        timestamp: intent.timestamp
      });

      // IMPORTANT: start from the original state, but do not mutate it
      let working: State = state;
      const denyReasons: ReasonCode[] = [];
      const t = intent.type ?? "EXECUTE";

      const results: PolicyResult[] =
        t === "RELEASE"
          ? [
              KillSwitchModule(intent, working),
              ReplayModule(intent, working),
              ConcurrencyModule(intent, working)
            ]
          : [
              KillSwitchModule(intent, working),
              AllowlistModule(intent, working),
              ReplayModule(intent, working),
              RecursionDepthModule(intent, working),
              ConcurrencyModule(intent, working),
              BudgetModule(intent, working),
              VelocityModule(intent, working)
            ];

      // Apply deltas in-order to working copy (deterministic), but still pure
      for (const r of results) {
        if (r.decision === "DENY") {
          denyReasons.push(...r.reasons);
          if (mode === "fail-fast") break;
        } else if (r.stateDelta) {
          working = deepMerge(working, r.stateDelta);
        }
      }

      if (denyReasons.length) {
        const out = { decision: "DENY" as const, reasons: denyReasons };
        this.audit.append({
          type: "DECISION",
          intent_hash,
          decision: "DENY",
          reasons: denyReasons,
          policy_version: state.policy_version,
          timestamp: intent.timestamp
        });
        return out;
      }

      // Authorization is now bound to nextState snapshot
      const state_snapshot_hash = sha256HexFromJson(working);
      const now = intent.timestamp;
      const expires_at = now + this.opts.authorization_ttl_seconds;

      const authPayload = {
        intent_hash,
        policy_version: state.policy_version,
        state_snapshot_hash,
        decision: "ALLOW" as const,
        expires_at
      };

      const engine_signature = engineSignHmac(authPayload, this.opts.engine_secret);
      const authorization_id = sha256HexFromJson({ ...authPayload, engine_signature });

      const authorization: Authorization = {
        authorization_id,
        intent_hash,
        policy_version: state.policy_version,
        state_snapshot_hash,
        decision: "ALLOW",
        expires_at,
        engine_signature
      };

      if (t === "EXECUTE") {
        const agent = intent.agent_id;
        const current = working.concurrency.active_auths?.[agent] ?? {};

        working = deepMerge(working, {
          concurrency: {
            ...working.concurrency,
            active_auths: {
              ...working.concurrency.active_auths,
              [agent]: {
                ...current,
                [authorization.authorization_id]: { expires_at: authorization.expires_at }
              }
            }
          }
        });
      }

      this.audit.append({
        type: "DECISION",
        intent_hash,
        decision: "ALLOW",
        reasons: [],
        policy_version: state.policy_version,
        timestamp: now
      });

      this.audit.append({
        type: "AUTH_EMITTED",
        authorization_id,
        intent_hash,
        expires_at,
        timestamp: now
      });

      return { decision: "ALLOW", reasons: [], authorization, nextState: working };
    } catch {
      return { decision: "DENY", reasons: ["INTERNAL_ERROR"] };
    }

    
  }
  
}
