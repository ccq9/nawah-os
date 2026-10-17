#!/usr/bin/env python3
"""Generates docs/schemas/*.schema.json (JSON Schema draft 2020-12).
Single source of truth for record schemas; run after any schema change.
schema_version of every record file is "1.0.0"."""
import json, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "schemas"
DRAFT = "https://json-schema.org/draft/2020-12/schema"
ID = {"type": "string", "pattern": "^[A-Z][A-Z0-9]*-[A-Za-z0-9.-]+$"}
IDS = {"type": "array", "items": ID, "uniqueItems": True}
STAGE = {"type": "string", "pattern": "^M[0-9]{1,2}$"}
STAGES = {"type": "array", "items": STAGE, "uniqueItems": True}
RELPATH = {"type": "string", "pattern": "^(?!/)(?!.*\\.\\.)[A-Za-z0-9_./-]+$"}
RELPATHS = {"type": "array", "items": RELPATH, "uniqueItems": True}
STR = {"type": "string", "minLength": 1}
STRS = {"type": "array", "items": STR}
SV = {"type": "string", "pattern": "^1\\.0\\.0$"}

def wrapper(item_schema, extra_required=()):
    return {
        "$schema": DRAFT, "type": "object", "additionalProperties": False,
        "required": ["schema_version", "records", *extra_required],
        "properties": {"schema_version": SV, "records": {"type": "array", "items": item_schema}},
    }

def obj(required, props):
    return {"type": "object", "additionalProperties": False, "required": required, "properties": props}

WI_STATUS = {"enum": ["planned", "active", "blocked", "done"]}
VERDICT = {"enum": ["PASS", "FAIL", "ERROR", "BLOCKED", "NOT_RUN", "N/A", "NEEDS_REEVALUATION"]}
CLAIM = {"enum": ["source_backed_fact", "logical_inference", "probability", "analytic_opinion", "unverified_assumption"]}

schemas = {
 "requirements": wrapper(obj(
   ["id","statement","rationale","source","origin","priority","release","stage","dependencies","contract_refs","failure_cases","acceptance","test_ids","implementation_status","evidence_refs"],
   {"id": ID, "statement": STR, "rationale": STR, "source": STR,
    "origin": {"enum": ["user_requirement","derived","recommendation","assumption"]},
    "priority": {"enum": ["must","should","could"]},
    "release": STR, "stage": STAGE, "dependencies": IDS, "contract_refs": RELPATHS,
    "failure_cases": STRS, "acceptance": STR, "test_ids": IDS,
    "implementation_status": {"enum": ["planned","partial","implemented_untested","verified_in_scope","blocked","deferred","out_of_scope"]},
    "evidence_refs": RELPATHS,
    "detail_status": {"enum": ["detailed","deferred"]},
    "detail_stage": STAGE, "defer_reason": STR})),
 "stages": wrapper(obj(
   ["id","name","depends_on","entry_conditions","exit_conditions","gate_status"],
   {"id": STAGE, "name": STR, "depends_on": STAGES, "entry_conditions": STRS, "exit_conditions": STRS,
    "gate_status": {"enum": ["not_started","open","passed","blocked"]}, "gate_evidence_refs": RELPATHS})),
 "work-items": wrapper(obj(
   ["id","stage","requirement_ids","depends_on","inputs","files","contract_refs","actions","acceptance","test_ids","commands","status","status_history","evidence_refs","blocker"],
   {"id": ID, "stage": STAGE, "requirement_ids": IDS, "depends_on": IDS, "inputs": STRS, "files": RELPATHS,
    "contract_refs": RELPATHS, "actions": STRS, "acceptance": STR, "test_ids": IDS, "commands": STRS,
    "status": WI_STATUS, "status_history": {"type": "array", "items": WI_STATUS, "minItems": 1},
    "evidence_refs": RELPATHS, "blocker": {"type": ["string","null"]}})),
 "tests": wrapper(obj(
   ["id","requirement_ids","layer","oracle","command","verdict","evidence_refs"],
   {"id": ID, "requirement_ids": IDS,
    "layer": {"enum": ["host_unit","guest","service_integration","user_e2e","negative","compat_hw","security_access_perf"]},
    "oracle": STR, "command": STR, "verdict": VERDICT, "evidence_refs": RELPATHS, "verdict_reason": STR})),
 "risks": wrapper(obj(
   ["id","risk","likelihood","impact","evidence","owner","warning_signal","mitigation","response_plan","status"],
   {"id": ID, "risk": STR, "likelihood": {"enum": ["low","medium","high"]}, "impact": {"enum": ["low","medium","high","critical"]},
    "evidence": STR, "owner": STR, "warning_signal": STR, "mitigation": STR, "response_plan": STR,
    "status": {"enum": ["open","mitigated","accepted","closed"]}})),
 "sources": wrapper(obj(
   ["id","title","url","version","accessed","supports","limits","verified"],
   {"id": ID, "title": STR, "url": STR, "version": STR, "accessed": {"type": ["string","null"]},
    "supports": STRS, "limits": STR, "verified": {"type": "boolean"}})),
 "hardware": wrapper(obj(
   ["id","target","model","spec_source","driver","support_limits","test_ids","evidence_refs"],
   {"id": ID, "target": STR, "model": STR, "spec_source": STR, "driver": STR, "support_limits": STR,
    "test_ids": IDS, "evidence_refs": RELPATHS})),
 "decisions-pending": wrapper(obj(
   ["id","question","options","recommendation","impact","blocked_task_ids","requested_at","status"],
   {"id": ID, "question": STR, "options": STRS, "recommendation": STR, "impact": STR,
    "blocked_task_ids": IDS, "requested_at": STR, "status": {"enum": ["open","answered","withdrawn"]}, "answer": STR})),
 "project-state": {
   "$schema": DRAFT, "type": "object", "additionalProperties": False,
   "required": ["schema_version","project_id","prompt_version","prompt_digest","project_root","source_revision","dirty_state",
                "current_stage","current_task","completed_requirement_ids","last_run_id","blockers","next_action","required_inputs",
                "runner_status","checkpoint_generation","event_sequence","pending_operations","budget_counters","next_retry_at",
                "cancellation_state","lease","host_fingerprint","errata_version","pending_decision_ids","unknown_fields"],
   "properties": {
     "schema_version": SV, "project_id": STR, "prompt_version": STR, "prompt_digest": STR, "project_root": STR,
     "source_revision": STR, "dirty_state": {"type": "boolean"}, "current_stage": STAGE, "current_task": {"type": ["string","null"]},
     "completed_requirement_ids": IDS, "last_run_id": {"type": ["string","null"]}, "blockers": STRS, "next_action": STR,
     "required_inputs": STRS, "runner_status": {"enum": ["idle","running","waiting_retry","blocked","cancelled","completed"]},
     "checkpoint_generation": {"type": "integer", "minimum": 0}, "event_sequence": {"type": "integer", "minimum": 0},
     "pending_operations": {"type": "array"}, "budget_counters": {"type": "object"}, "next_retry_at": {"type": ["string","null"]},
     "cancellation_state": {"enum": ["none","requested","cancelled"]}, "lease": {"type": ["object","null"]},
     "host_fingerprint": STR, "errata_version": STR, "pending_decision_ids": IDS,
     "unknown_fields": {"type": "object", "description": "field -> reason it is unknown (no default values for unknowns)"}}},
 "automation": {
   "$schema": DRAFT, "type": "object", "additionalProperties": False,
   "required": ["schema_version","mode","verification_runner","development_worker","worker_command","worker_version","supervisor",
                "persistent_store","persistence_verified_by","lease_policy","workspace_root","allowed_targets","permission_refs",
                "retry_policy","operation_timeouts","budgets","concurrency_limit","checkpoint_policy","cancellation_policy",
                "restart_policy","context_policy"],
   "properties": {
     "schema_version": SV, "mode": {"enum": ["interactive","durable","text_only"]},
     "verification_runner": {"type": "object"}, "development_worker": {"type": "object"},
     "worker_command": {"type": ["string","null"]}, "worker_version": {"type": ["string","null"]}, "supervisor": {"type": ["string","null"]},
     "persistent_store": {"type": "object"}, "persistence_verified_by": {"type": ["string","null"]}, "lease_policy": {"type": "object"},
     "workspace_root": STR, "allowed_targets": STRS, "permission_refs": STRS, "retry_policy": {"type": "object"},
     "operation_timeouts": {"type": "object"}, "budgets": {"type": "object"}, "concurrency_limit": {"type": "integer", "minimum": 1},
     "checkpoint_policy": {"type": "object"}, "cancellation_policy": {"type": "object"}, "restart_policy": {"type": "object"},
     "context_policy": {"type": "object"}}},
 "evidence-run": {
   "$schema": DRAFT, "type": "object", "additionalProperties": False,
   "required": ["schema_version","run_id","started_at","finished_at","source_revision","dirty_state","host","target","worker","purpose","commands","exit_code"],
   "properties": {"schema_version": SV, "run_id": STR, "started_at": STR, "finished_at": STR, "source_revision": STR,
                  "dirty_state": {"type": "boolean"}, "host": {"type": "object"}, "target": STR, "worker": STR, "purpose": STR,
                  "commands": STRS, "exit_code": {"type": "integer"}, "notes": STR}},
 "evidence-verdict": {
   "$schema": DRAFT, "type": "object", "additionalProperties": False,
   "required": ["schema_version","run_id","test_id","verdict","oracle","expected","observed","inputs_digest","inputs","claim_tag"],
   "properties": {"schema_version": SV, "run_id": STR, "test_id": ID, "verdict": VERDICT, "oracle": STR, "expected": STR,
                  "observed": STR, "inputs_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                  "inputs": {"type": "object", "additionalProperties": {"type": "string", "pattern": "^[0-9a-f]{64}$"}},
                  "claim_tag": CLAIM, "reason": STR}},
 "event": {
   "$schema": DRAFT, "type": "object", "additionalProperties": False,
   "required": ["schema_version","project_id","run_id","operation_id","task_id","seq","type","inputs_digest","state","result","evidence_ref","recorded_at","fencing_token"],
   "properties": {"schema_version": SV, "project_id": STR, "run_id": {"type": ["string","null"]}, "operation_id": STR,
                  "task_id": {"type": ["string","null"]}, "seq": {"type": "integer", "minimum": 1}, "type": STR,
                  "inputs_digest": {"type": ["string","null"]}, "state": STR, "result": {"type": ["string","null"]},
                  "evidence_ref": {"type": ["string","null"]}, "recorded_at": STR, "fencing_token": {"type": "integer"}}},
}

if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for name, schema in schemas.items():
        p = OUT / f"{name}.schema.json"
        p.write_text(json.dumps(schema, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print("wrote", p.relative_to(ROOT))
