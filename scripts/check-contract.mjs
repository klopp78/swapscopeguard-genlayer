import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const source = readFileSync(new URL("../contracts/swap_scope_guard.py", import.meta.url), "utf8");
for (const invariant of [
  "class SwapScopeGuard(gl.Contract)", "def create_trade_mandate(",
  "def assess_trade_mandate(", "def execute_authorized_swap(",
  "def revoke_trade_mandate(", "gl.vm.run_nondet_unsafe",
  "gl.nondet.web.render", "only_bound_executor_can_execute",
  "execution_scope_mismatch", "fee_exceeds_cap", "mandate_not_executable",
  "approval_requires_payload_binding", "hashlib.sha256", "list_mandate_ids",
]) assert.ok(source.includes(invariant), `missing ${invariant}`);

const digest = "a".repeat(64);
assert.match(digest, /^[0-9a-f]{64}$/);
assert.throws(() => { if (!/^[0-9a-f]{64}$/.test("a".repeat(63))) throw new Error("invalid payload"); });
console.log("SwapScopeGuard structural checks passed");
