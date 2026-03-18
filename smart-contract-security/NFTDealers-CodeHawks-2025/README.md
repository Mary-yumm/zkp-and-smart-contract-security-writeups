# NFT Dealers — CodeHawks First Flight #58

## Contest Details

| | |
|---|---|
| **Platform** | CodeHawks First Flights |
| **Type** | Beginner Friendly |
| **Dates** | March 12, 2026 – March 19, 2026 |
| **nSLOC** | 253 |
| **Original Repo** | [CodeHawks-Contests/2026-03-NFT-dealers](https://github.com/CodeHawks-Contests/2026-03-NFT-dealers) |
| **Commit in Scope** | `main` |

---

## About the Protocol

NFT Dealers is a marketplace contract for minting and reselling NFTs with a progressive fee structure (1%, 3%, or 5% depending on sale price). Users pay a USDC collateral on mint which is returned upon sale. The contract has two phases — a preparation phase where the owner whitelists wallets, and a revealed phase where whitelisted users can mint, list, buy, and collect proceeds.

---

## My Results

| Severity | Found | 
|---|---|
| High | 4 | 
| Medium | 5 | 
| Low | 7 | 
| Informational | 5 |

---

## Findings Summary

### High

| ID | Title |
|---|---|
| [H-1](findings.md#h-1-missing-zero-address-checks-for-_owner-and-_usdc-in-constructor) | Missing Zero Address Checks for `_owner` and `_usdc` in Constructor |
| [H-2](findings.md#h-2-cross-function-reentrancy-across-buy-cancellisting-and-collectusdcfromselling) | Cross-Function Reentrancy Across `buy`, `cancelListing`, and `collectUsdcFromSelling` |
| [H-3](findings.md#h-3-collectusdcfromselling-transfers-fees-to-addressthis--self-transfer-bug) | `collectUsdcFromSelling` Transfers Fees to `address(this)` — Self-Transfer Bug |
| [H-4](findings.md#h-4-s_listings-is-keyed-by-token-id-but-events-emit-listingscounter-as-the-listing-id) | `s_listings` Keyed by Token ID but Events Emit `listingsCounter` as the Listing ID |

### Medium

| ID | Title |
|---|---|
| [M-1](findings.md#m-1-contract-accepts-eth-but-has-no-withdrawal-function) | Contract Accepts ETH but Has No Withdrawal Function |
| [M-2](findings.md#m-2-listingprice-declared-as-uint32-caps-maximum-sale-price-at-4294-usdc) | `Listing.price` Declared as `uint32` Caps Maximum Sale Price at ~4,294 USDC |
| [M-3](findings.md#m-3-buy-lacks-onlywhitelisted-modifier--anyone-can-purchase-nfts) | `buy()` Lacks `onlyWhitelisted` Modifier — Anyone Can Purchase NFTs |
| [M-4](findings.md#m-4-collectusdcfromselling-does-not-zero-out-collateralforminting-enabling-double-collection) | `collectUsdcFromSelling` Does Not Zero Out `collateralForMinting`, Enabling Double-Collection |
| [M-5](findings.md#m-5-raw-transferfrom-used-instead-of-safetransferfrom-in-mintnft-and-buy) | Raw `transferFrom` Used Instead of `safeTransferFrom` in `mintNft` and `buy` |

### Low

| ID | Title |
|---|---|
| [L-1](findings.md#l-1-floating-pragma-allows-compilation-with-unintended-compiler-versions) | Floating Pragma Allows Compilation with Unintended Compiler Versions |
| [L-2](findings.md#l-2-constructor-parameter-_symbol-shadows-erc721_symbol) | Constructor Parameter `_symbol` Shadows `ERC721._symbol` |
| [L-3](findings.md#l-3-token-id-counter-increments-before-minting--token-id-0-is-permanently-skipped) | Token ID Counter Increments Before Minting — Token ID 0 Is Permanently Skipped |
| [L-4](findings.md#l-4-multiple-state-changing-functions-emit-no-events) | Multiple State-Changing Functions Emit No Events |
| [L-5](findings.md#l-5-updateprice-reads-oldprice-before-checking-listing-is-active) | `updatePrice` Reads `oldPrice` Before Checking Listing Is Active |
| [L-6](findings.md#l-6-precision-loss-in-fee-calculation-due-to-integer-division-truncation) | Precision Loss in Fee Calculation Due to Integer Division Truncation |
| [L-7](findings.md#l-7-calculatefees-public-wrapper-must-be-removed-before-production-deployment) | `calculateFees` Public Wrapper Must Be Removed Before Production Deployment |

### Informational

| ID | Title |
|---|---|
| [I-1](findings.md#i-1-state-variables-set-only-in-constructor-should-be-declared-immutable) | State Variables Set Only in Constructor Should Be Declared `immutable` |
| [I-2](findings.md#i-2-explicit-boolean-comparison-to-false-should-use-negation-operator) | Explicit Boolean Comparison to `false` Should Use Negation Operator |
| [I-3](findings.md#i-3-mintnft-contains-an-impossible-zero-address-check-for-msgsender) | `mintNft` Contains an Impossible Zero Address Check for `msg.sender` |
| [I-4](findings.md#i-4-metadatafrozen-is-declared-but-never-set-or-checked--freeze-feature-is-incomplete) | `metadataFrozen` Is Declared but Never Set or Checked — Freeze Feature Is Incomplete |
| [I-5](findings.md#i-5-max_bps-literal-should-use-scientific-notation-for-consistency) | `MAX_BPS` Literal Should Use Scientific Notation for Consistency |

---

## Key Takeaways

- The most critical bug was a **self-transfer no-op in `collectUsdcFromSelling`** — `usdc.safeTransfer(address(this), fees)` is a complete no-op since the contract is transferring to itself, but `totalFeesCollected` keeps accumulating. This means `withdrawFees` will over-draw from the contract balance and steal funds from other users.
- A **listing ID / token ID mismatch** means any event-driven interaction with the marketplace (the standard frontend pattern) would consistently query the wrong listing slot.
- The contract has **no reentrancy protection** despite making multiple external calls in `buy`, `cancelListing`, and `collectUsdcFromSelling`.
- Both `mintNft` and `buy` are marked `payable` but the contract has no ETH withdrawal path, permanently locking any ETH sent by accident.
