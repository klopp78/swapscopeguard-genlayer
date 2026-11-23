# SwapScopeGuard for GenLayer

SwapScopeGuard is a GenLayer Intelligent Contract for AI-agent token swaps. An owner creates a canonical one-use mandate that binds the executor, chain, router, token pair, input amount, minimum output, slippage cap, maximum fee, expiry, quote URL, and calldata/payload SHA-256 commitment.

Validators independently retrieve the supplied quote and run consensus adjudication. Only an approved mandate can be consumed, only by its named executor, before expiry, with the exact bound trade fields. Every write persists an immutable receipt hash and the registry is paginated for discovery.

## Lifecycle

1. `create_trade_mandate` creates the owner-bound canonical scope.
2. `assess_trade_mandate` retrieves evidence and writes an approved, blocked, or inconclusive consensus receipt.
3. `execute_authorized_swap` verifies the executor, scope, payload hash, fee cap, expiry, and replay protection before recording consumption.
4. `revoke_trade_mandate` lets the owner cancel an unused mandate.

## Verification

```bash
npm test
```
