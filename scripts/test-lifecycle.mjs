import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const hash = (v) => createHash("sha256").update(v).digest("hex");
const owner = "0x1111111111111111111111111111111111111111";
const executor = "0x2222222222222222222222222222222222222222";
const stranger = "0x3333333333333333333333333333333333333333";
const scope = { owner, executor, router: "0x4444444444444444444444444444444444444444", tokenIn: "0x5555555555555555555555555555555555555555", tokenOut: "0x6666666666666666666666666666666666666666", amount: 1000, minOut: 950, maxFee: 25, payload: hash("swap calldata"), expiry: 4000 };
const receipt = { status: "approved", scopeHash: hash(JSON.stringify(scope)), consumed: false };
function execute(sender, candidate, now) {
  assert.equal(receipt.status, "approved");
  assert.equal(receipt.consumed, false, "replay must fail");
  assert.equal(sender, scope.executor, "executor must be bound");
  assert.ok(now <= scope.expiry, "must be unexpired");
  assert.deepEqual(candidate, { router: scope.router, tokenIn: scope.tokenIn, tokenOut: scope.tokenOut, amount: scope.amount, minOut: scope.minOut, payload: scope.payload, fee: 12 });
  receipt.consumed = true;
  return hash(receipt.scopeHash + ":executed");
}
assert.throws(() => execute(stranger, {}, 3000));
assert.throws(() => execute(executor, { router: scope.router, tokenIn: scope.tokenIn, tokenOut: scope.tokenOut, amount: scope.amount, minOut: scope.minOut, payload: scope.payload, fee: 100 }, 3000));
const ok = { router: scope.router, tokenIn: scope.tokenIn, tokenOut: scope.tokenOut, amount: scope.amount, minOut: scope.minOut, payload: scope.payload, fee: 12 };
assert.match(execute(executor, ok, 3000), /^[0-9a-f]{64}$/);
assert.throws(() => execute(executor, ok, 3000));
console.log("SwapScopeGuard lifecycle checks passed");
