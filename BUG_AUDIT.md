# Serious Logic Bug Audit

Status legend: `[ ]` open, `[~]` investigating/fixing, `[x]` fixed.

## Findings

- [ ] **Critical: missing authorization count check permits unauthorized spends.**
  - Paths: `lib/state/mod.rs:689`, `lib/state/block.rs:82`, `lib/authorization.rs:168`.
  - Issue: validation zips authorizations with inputs/spent UTXOs, so short or empty auth lists skip unchecked inputs; batch verification only verifies provided auths.
  - Fix shape: require `authorizations.len() == total_input_count` before address/signature checks in transaction and block validation.

- [ ] **High: `filled_outputs()` accepts leftover required asset outputs.**
  - Path: `lib/types/transaction/mod.rs:1567`.
  - Issue: oversized outputs are rejected, but unconsumed BitAsset/LP/reservation/auction iterators are not checked after output processing.
  - Impact: partial asset outputs can silently destroy/desync non-Bitcoin assets while validation passes.
  - Fix shape: after collecting outputs, verify all required iterators and remaining amounts are exhausted/zero.

- [ ] **High: AMM mint validates LP issuance against wrong baseline.**
  - Path: `lib/state/amm.rs:416`.
  - Issue: compares `new_outstanding_lp_tokens - lp_token_mint == lp_token_mint`; should compare `new_outstanding_lp_tokens - old_outstanding_lp_tokens == lp_token_mint`.
  - Impact: correct RPC/GUI mint txs can be rejected; crafted txs can create phantom outstanding LP supply.

- [ ] **High: AMM/auction validation uses input count as unique output count.**
  - Path: `lib/state/mod.rs:552`.
  - Issue: `n_unique_bitasset_outputs` is assigned `tx.unique_spent_bitassets().len()`, which counts unique spent inputs, not outputs.
  - Impact: AMM burn/mint/swap and auction shape checks reject/misvalidate core flows.
  - Fix shape: compute unique BitAsset IDs from actual `tx.bitasset_outputs()` after filling, not from spent inputs.

- [ ] **High: withdrawal-event disconnect deletes the wrong DB.**
  - Path: `lib/state/two_way_peg_data.rs:916`.
  - Issue: after reading `withdrawal_bundle_event_blocks`, rollback deletes from `deposit_blocks`.
  - Impact: reorg over withdrawal events can corrupt deposit tracking and leave stale withdrawal-event metadata.
  - Fix shape: delete from `withdrawal_bundle_event_blocks`.

- [ ] **Medium: withdrawal bundle output limit is off by one.**
  - Path: `lib/state/two_way_peg_data.rs:87`.
  - Issue: loop breaks on `len() > MAX_BUNDLE_OUTPUTS`, allowing `MAX + 1` outputs before weight check.
  - Impact: enough unique withdrawal destinations can repeatedly make bundle collection fail as too heavy.
  - Fix shape: break on `>=` before pushing, or cap with `take(MAX_BUNDLE_OUTPUTS)`.

- [ ] **Medium: sidechain wealth subtracts withdrawals from wrong accumulator.**
  - Path: `lib/state/mod.rs:763`.
  - Issue: assigns `total_withdrawal_stxo_value = total_deposit_stxo_value.checked_add(...)`.
  - Impact: reported sidechain wealth can be wrong after withdrawals.
  - Fix shape: accumulate into `total_withdrawal_stxo_value`.

## Verification Notes

- Ran: `cargo test -p plain_bitassets --lib --no-run`.
- Result: library test target compiled.
- Gap: full integration tests not run; no malicious transaction regression tests found for these paths.

## Regression Test Ideas

- A tx with one input and zero authorizations must fail validation.
- A tx with two inputs and one valid authorization must fail validation.
- A BitAsset tx spending `N` units and outputting less than required must fail `filled_outputs`/validation.
- AMM mint created by RPC/GUI path should validate and apply with LP delta equal to `new - old`.
- Reorg/disconnect over a withdrawal bundle event should remove only `withdrawal_bundle_event_blocks`.
