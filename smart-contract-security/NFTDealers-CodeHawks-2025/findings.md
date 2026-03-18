# NFTDealers Audit Findings

---

## High Severity

---

### [H-1] Missing Zero Address Checks for `_owner` and `_usdc` in Constructor

**Impact**: High | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

If `_owner` or `_usdc` is set to `address(0)` at deployment, all owner-gated functions become permanently inaccessible and every USDC operation reverts, bricking the contract entirely with no recovery path.

---

#### Description

- The constructor assigns `_owner` and `_usdc` directly without validating that they are non-zero addresses
- There is no way to update these values post-deployment since `owner` has no setter and `usdc` is immutable, making a bad deployment unrecoverable

```solidity
constructor(
    address _owner,
    address _usdc,
    ...
) ERC721(_collectionName, _symbol) {
    // @audit no zero address check before assignment
    owner = _owner;
    usdc = IERC20(_usdc);
}
```

---

#### Risk

**Likelihood:**
- Occurs at deployment time — a single misconfigured deploy script or copy-paste error is enough to trigger this
- No on-chain safeguard exists to catch the mistake after the fact

**Impact:**
- If `_owner == address(0)`: `revealCollection`, `whitelistWallet`, `removeWhitelistedWallet`, and `withdrawFees` are permanently locked
- If `_usdc == address(0)`: every call to `mintNft`, `buy`, `cancelListing`, `collectUsdcFromSelling`, and `withdrawFees` reverts, making the contract completely non-functional

---

#### Proof of Concept

The following demonstrates deploying with a zero owner address. Because `owner` is set to `address(0)` and never updatable, the `onlyOwner` modifier will revert on every privileged call for the entire lifetime of the contract.

```solidity
NFTDealers dealers = new NFTDealers(
    address(0), // _owner set to zero by mistake
    address(usdc),
    "MyNFT",
    "NFT",
    "ipfs://image",
    20e6
);

// All onlyOwner functions permanently revert
dealers.revealCollection(); // reverts: "Only owner can call this function"
dealers.whitelistWallet(alice); // reverts
dealers.withdrawFees(); // reverts
```

---

#### Recommended Mitigation

Add a guard at the very top of the constructor body using the existing `InvalidAddress` custom error. This ensures any misconfigured deployment reverts immediately at deploy time rather than silently producing a broken contract. Both addresses must be checked independently since either being zero causes a distinct failure mode.

```diff
  constructor(
      address _owner,
      address _usdc,
      ...
  ) ERC721(_collectionName, _symbol) {
+     if (_owner == address(0) || _usdc == address(0)) revert InvalidAddress();
      owner = _owner;
      usdc = IERC20(_usdc);
      ...
  }
```

---

### [H-2] Cross-Function Reentrancy Across `buy`, `cancelListing`, and `collectUsdcFromSelling`

**Impact**: High | **Likelihood**: Medium
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

Multiple functions perform external calls before finalising state updates, violating the Checks-Effects-Interactions (CEI) pattern. A malicious token with transfer hooks can re-enter the contract and drain funds or manipulate listing state.

---

#### Description

- `buy()` calls `_safeTransfer` before setting `s_listings[_listingId].isActive = false`, allowing a reentrant call to purchase the same listing again
- `cancelListing()` calls `usdc.safeTransfer` before zeroing `collateralForMinting`, allowing a reentrant call to drain collateral multiple times
- `collectUsdcFromSelling()` has no reentrancy guard and makes two consecutive external `safeTransfer` calls with no state finalization in between
- No `ReentrancyGuard` is applied anywhere in the contract

```solidity
// buy() — isActive is set AFTER the external NFT transfer
_safeTransfer(listing.seller, msg.sender, listing.tokenId, "");
// @audit reentrant call can re-enter buy() here before isActive = false
s_listings[_listingId].isActive = false;
```

---

#### Risk

**Likelihood:**
- Requires a malicious or hook-enabled ERC20 token, or a buyer contract that implements `onERC721Received` to re-enter
- More likely in permissionless or upgradeable token deployments

**Impact:**
- Attacker can buy the same NFT listing multiple times before `isActive` is set to false
- Attacker can drain collateral from `cancelListing` by re-entering before `collateralForMinting` is zeroed
- Contract USDC balance can be fully drained in a single transaction

---

#### Proof of Concept

Since `_safeTransfer` calls `onERC721Received` on the recipient before `isActive` is set to false, an attacker can deploy a contract that re-enters `buy()` inside that callback. Each reentrant call sees the listing as still active and successfully purchases the NFT again, draining USDC from the contract on every iteration until the balance is exhausted.

```solidity
contract Attacker {
    NFTDealers nftDealers;
    uint256 listingId;

    function attack(uint256 _listingId) external {
        listingId = _listingId;
        nftDealers.buy(_listingId);
    }

    // Called by _safeTransfer before isActive is set to false
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        // Listing is still active — re-enter and drain again
        nftDealers.buy(listingId);
        return this.onERC721Received.selector;
    }
}
```

---

#### Recommended Mitigation

Two complementary fixes should be applied together. First, inherit OpenZeppelin's `ReentrancyGuard` and apply `nonReentrant` to all functions that make external calls. Second, restructure each affected function to follow the CEI pattern — all state changes must complete before any external call is made. This ensures that even if a reentrant call is attempted, the state will already reflect the completed operation and the call will revert.

```diff
+ import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

- contract NFTDealers is ERC721 {
+ contract NFTDealers is ERC721, ReentrancyGuard {

- function buy(uint256 _listingId) external payable {
+ function buy(uint256 _listingId) external payable nonReentrant {
      Listing memory listing = s_listings[_listingId];
      if (!listing.isActive) revert ListingNotActive(_listingId);
      require(listing.seller != msg.sender, "Seller cannot buy their own NFT");
+     // Effects before interactions
+     s_listings[_listingId].isActive = false;
+     activeListingsCounter--;
      usdc.safeTransferFrom(msg.sender, address(this), listing.price);
      _safeTransfer(listing.seller, msg.sender, listing.tokenId, "");
-     s_listings[_listingId].isActive = false;
-     activeListingsCounter--;
      emit NFT_Dealers_Sold(msg.sender, listing.price);
  }
```

---

### [H-3] `collectUsdcFromSelling` Transfers Fees to `address(this)` — Self-Transfer Bug

**Impact**: High | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

The fee transfer in `collectUsdcFromSelling` sends USDC back to the contract itself, making it a no-op. Meanwhile `totalFeesCollected` keeps accumulating, causing `withdrawFees` to over-draw from the contract balance and steal funds belonging to other users.

---

#### Description

- `usdc.safeTransfer(address(this), fees)` transfers to the contract itself — the balance does not change
- `totalFeesCollected` is still incremented by `fees` on every call, making the accounting inconsistent with the actual isolated fee balance
- When the owner calls `withdrawFees`, it withdraws `totalFeesCollected` from the general contract balance, which includes USDC that belongs to other sellers as collateral or pending proceeds

```solidity
totalFeesCollected += fees;
// @audit transfers to itself — this is a no-op, fees are not isolated
usdc.safeTransfer(address(this), fees);
usdc.safeTransfer(msg.sender, amountToSeller);
```

---

#### Risk

**Likelihood:**
- Triggered every time any seller calls `collectUsdcFromSelling` — this is the normal happy path
- No special conditions required

**Impact:**
- `withdrawFees` drains USDC that belongs to other users' collateral or pending proceeds
- Sellers who have not yet called `collectUsdcFromSelling` may find the contract balance insufficient when they do, causing their transactions to revert
- Protocol fee accounting is entirely broken

---

#### Proof of Concept

The scenario below shows how the self-transfer causes `totalFeesCollected` to diverge from the actual available fee balance. When `withdrawFees` is called, it attempts to withdraw an amount larger than what the fees actually represent, pulling USDC from funds that belong to other participants in the protocol.

```solidity
// Setup: Alice and Bob each sell an NFT for 1000 USDC (fee = 10 USDC each)

// Step 1: Alice collects proceeds
dealers.collectUsdcFromSelling(aliceListingId);
// Alice receives 990 USDC + 20 USDC collateral = 1010 USDC
// usdc.safeTransfer(address(this), 10) is a no-op — nothing is isolated
// totalFeesCollected = 10

// Step 2: Bob collects proceeds
dealers.collectUsdcFromSelling(bobListingId);
// totalFeesCollected = 20

// Step 3: Owner withdraws fees
// withdrawFees sends 20 USDC to owner
// But only 10 USDC of real fees were generated — the other 10 USDC belongs to Bob
dealers.withdrawFees(); // steals 10 USDC from remaining contract balance
```

---

#### Recommended Mitigation

Remove the self-transfer line entirely. The USDC is already held in the contract's balance when a buyer calls `buy()`, so there is nothing to move — the fees are implicitly retained by not paying them out to the seller. The `totalFeesCollected` counter alone is sufficient for `withdrawFees` to know how much to send to the owner. Removing the no-op line also saves gas on every seller payout.

```diff
  totalFeesCollected += fees;
- usdc.safeTransfer(address(this), fees); // remove — no-op, fees already held in contract balance
  usdc.safeTransfer(msg.sender, amountToSeller);
```

---

### [H-4] `s_listings` Is Keyed by Token ID but Events Emit `listingsCounter` as the Listing ID

**Impact**: High | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

The `list()` function stores listings in `s_listings` using `_tokenId` as the key but emits `listingsCounter` as the listing ID in the event. Any caller using the emitted ID to interact with `buy()`, `cancelListing()`, or `updatePrice()` will query the wrong mapping slot, interacting with a different listing or causing unexpected reverts.

---

#### Description

- `s_listings[_tokenId]` is the storage key, but `emit NFT_Dealers_Listed(msg.sender, listingsCounter)` exposes `listingsCounter` as the public identifier
- All downstream functions (`buy`, `cancelListing`, `updatePrice`, `collectUsdcFromSelling`) accept a `_listingId` and look up `s_listings[_listingId]`
- When a user passes the emitted `listingsCounter` value into these functions, they access a completely different slot than intended

```solidity
// list()
s_listings[_tokenId] = Listing({...});               // keyed by tokenId
emit NFT_Dealers_Listed(msg.sender, listingsCounter); // @audit emits listingsCounter — different value
```

---

#### Risk

**Likelihood:**
- Any frontend or user that relies on the emitted event to determine the listing ID (the standard pattern) will use the wrong ID every time
- The mismatch is systemic — it affects every listing in the contract

**Impact:**
- Buyers cannot reliably purchase a specific listing using the event-emitted ID
- `cancelListing` and `updatePrice` will operate on wrong listings
- The `onlySeller` modifier check will fail or pass for unintended listings, breaking access control

---

#### Proof of Concept

Consider a marketplace with several existing listings. Token IDs and listing counter values will diverge quickly, causing every event-driven interaction to target the wrong listing. In the example below, acting on the emitted listing ID results in purchasing a completely different NFT than intended — or reverting entirely if that slot is inactive.

```solidity
// State: tokens 1–4 have been minted, tokens 1–3 already listed (listingsCounter = 3)

// Token ID 5 is now listed — listingsCounter becomes 4
dealers.list(5, 500e6);
// Event emits: NFT_Dealers_Listed(seller, 4)  <-- listingsCounter value

// Buyer reads the event, sees listingId = 4, and calls buy(4)
dealers.buy(4); // looks up s_listings[4] — that is token ID 4's listing, NOT token ID 5's
// Buyer gets the wrong NFT or the call reverts with ListingNotActive
```

---

#### Recommended Mitigation

The fix is to align the storage key with the value published in the event. Since `listingsCounter` is already being incremented and emitted, it should also be used as the mapping key. The `tokenId` is already stored inside the `Listing` struct, so no information is lost — callers can retrieve the token ID from the struct after looking up by listing ID.

```diff
  function list(uint256 _tokenId, uint32 _price) external onlyWhitelisted {
      ...
      listingsCounter++;
      activeListingsCounter++;

-     s_listings[_tokenId] = Listing({
-         seller: msg.sender,
-         price: _price,
-         nft: address(this),
-         tokenId: _tokenId,
-         isActive: true
-     });
+     s_listings[listingsCounter] = Listing({
+         seller: msg.sender,
+         price: _price,
+         nft: address(this),
+         tokenId: _tokenId,
+         isActive: true
+     });
      emit NFT_Dealers_Listed(msg.sender, listingsCounter);
  }
```

---

## Medium Severity

---

### [M-1] Contract Accepts ETH but Has No Withdrawal Function

**Impact**: Medium | **Likelihood**: Medium
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

`mintNft` and `buy` are marked `payable` but the contract has no ETH withdrawal path. Any ETH sent to these functions is permanently locked with no recovery mechanism.

---

#### Description

- Both `mintNft` and `buy` have the `payable` modifier despite not requiring ETH for any operation
- There is no `withdraw`, `receive`, or `fallback` function to recover ETH
- Users sending ETH accidentally (common with scripted interactions or wallet UX errors) have no recourse

```solidity
// @audit payable but ETH is never used or recoverable
function mintNft() external payable onlyWhenRevealed onlyWhitelisted { ... }
function buy(uint256 _listingId) external payable { ... }
```

---

#### Risk

**Likelihood:**
- Any user who sends ETH alongside a call — whether by mistake or due to a frontend bug — triggers this
- Scripted deployments or bots are especially prone to attaching ETH unintentionally

**Impact:**
- ETH sent is permanently lost with no recovery mechanism
- Silently accumulates over time, increasing the total loss

---

#### Proof of Concept

Because both functions are `payable`, the EVM accepts any ETH attached to the call without complaint. There is no path to retrieve it — no withdrawal function, no `receive()`, and no event to even detect that it happened. The test below confirms ETH is trapped immediately on the first interaction.

```solidity
// User accidentally sends 1 ETH alongside the mint call (e.g. wrong field in a script)
dealers.mintNft{value: 1 ether}();

// ETH is now permanently locked — no function exists to retrieve it
assertEq(address(dealers).balance, 1 ether); // unrecoverable
```

---

#### Recommended Mitigation

The simplest fix is to remove `payable` from both functions, causing the EVM to automatically revert any call that attaches ETH. If the contract intentionally needs to accept ETH for a future use case, an owner-only withdrawal function should be added to ensure funds are never permanently stranded.

```diff
- function mintNft() external payable onlyWhenRevealed onlyWhitelisted {
+ function mintNft() external onlyWhenRevealed onlyWhitelisted {

- function buy(uint256 _listingId) external payable {
+ function buy(uint256 _listingId) external {
```

If ETH acceptance is intentional, add a dedicated withdrawal function alongside the `payable` modifier:

```diff
+ function withdrawEth() external onlyOwner {
+     (bool success, ) = owner.call{value: address(this).balance}("");
+     require(success, "ETH withdrawal failed");
+ }
```

---

### [M-2] `Listing.price` Declared as `uint32` Caps Maximum Sale Price at ~4,294 USDC

**Impact**: Medium | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

The `price` field in the `Listing` struct and all related function parameters are `uint32`. With USDC at 6 decimals, this silently caps the maximum listing price at approximately 4,294 USDC, making high-value NFT sales impossible.

---

#### Description

- `uint32` maximum value is `4,294,967,295`
- USDC uses 6 decimal places, so `4,294,967,295` corresponds to approximately 4,294 USDC
- Prices above this threshold will truncate on cast with no informative error, silently corrupting the stored price

```solidity
struct Listing {
    address seller;
    uint32 price; // @audit max ~4,294 USDC with 6 decimals
    address nft;
    uint256 tokenId;
    bool isActive;
}
```

---

#### Risk

**Likelihood:**
- Any seller attempting to list an NFT above ~4,294 USDC hits this cap
- NFT markets routinely involve values well above this threshold

**Impact:**
- High-value listings are silently corrupted or impossible to create
- Sellers may unknowingly list at the wrong price due to silent truncation

---

#### Proof of Concept

USDC amounts are expressed with 6 decimal places, so a 10,000 USDC listing requires passing `10_000e6 = 10_000_000_000`. This value exceeds `uint32`'s maximum of `4,294,967,295`, so casting it truncates the value silently. The listing is stored with a drastically wrong price and the seller has no indication that anything went wrong.

```solidity
// Seller intends to list for 10,000 USDC
uint256 intendedPrice = 10_000e6; // = 10_000_000_000

// uint32 max             = 4_294_967_295
// uint32(10_000_000_000) = 1_705_032_704  (~1,705 USDC — wrong)
dealers.list(tokenId, uint32(intendedPrice)); // silently stores 1,705 USDC instead of 10,000 USDC
```

---

#### Recommended Mitigation

Change `price` in the `Listing` struct and all associated function parameters from `uint32` to `uint256`. Since USDC amounts are denominated in 6-decimal units, `uint256` gives ample headroom for any realistic price and eliminates the truncation risk entirely. The storage cost difference between `uint32` and `uint256` is negligible given the other fields already occupy a full slot.

```diff
  struct Listing {
      address seller;
-     uint32 price;
+     uint256 price;
      address nft;
      uint256 tokenId;
      bool isActive;
  }

- function list(uint256 _tokenId, uint32 _price) external onlyWhitelisted {
+ function list(uint256 _tokenId, uint256 _price) external onlyWhitelisted {

- function updatePrice(uint256 _listingId, uint32 _newPrice) external onlySeller(_listingId) {
+ function updatePrice(uint256 _listingId, uint256 _newPrice) external onlySeller(_listingId) {
```

---

### [M-3] `buy()` Lacks `onlyWhitelisted` Modifier — Anyone Can Purchase NFTs

**Impact**: Medium | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

Minting and listing both require whitelist membership, but `buy()` has no such restriction. Non-whitelisted addresses can freely purchase NFTs, bypassing the access control design entirely.

---

#### Description

- `mintNft` uses `onlyWhitelisted` to restrict who can participate as a minter
- `list` uses `onlyWhitelisted` to restrict who can create listings
- `buy` has no access control modifier, making the whitelist system one-sided

```solidity
// Listing correctly requires whitelist
function list(uint256 _tokenId, uint32 _price) external onlyWhitelisted { ... }

// @audit buy has no whitelist check — any address can call this
function buy(uint256 _listingId) external payable { ... }
```

---

#### Risk

**Likelihood:**
- Any address not on the whitelist can call `buy()` immediately — no special conditions needed

**Impact:**
- The curated marketplace access control is broken on the buy side
- Non-whitelisted actors can acquire NFTs and participate in the ecosystem without approval

---

#### Proof of Concept

The test below shows that `buy()` succeeds for an address that has never been added to the whitelist. The `onlyWhitelisted` modifier is present on every other user-facing function, so this omission is clearly inconsistent with the intended design.

```solidity
address randomUser = makeAddr("randomUser");

// Confirm randomUser is not whitelisted
assertFalse(dealers.isWhitelisted(randomUser));

// randomUser purchases an NFT without any issue
vm.startPrank(randomUser);
usdc.approve(address(dealers), listingPrice);
dealers.buy(listingId); // succeeds — whitelist is not enforced here
vm.stopPrank();
```

---

#### Recommended Mitigation

Add the `onlyWhitelisted` modifier to `buy()` to bring it in line with the access control applied to all other participant-facing functions. This ensures only approved addresses can interact with the marketplace on both the supply and demand sides.

```diff
- function buy(uint256 _listingId) external payable {
+ function buy(uint256 _listingId) external onlyWhitelisted {
```

---

### [M-4] `collectUsdcFromSelling` Does Not Zero Out `collateralForMinting`, Enabling Double-Collection

**Impact**: Medium | **Likelihood**: Medium
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

`collateralForMinting[listing.tokenId]` is read and added to the seller's payout but is never reset to zero. A seller can call `collectUsdcFromSelling` multiple times on the same inactive listing and drain extra USDC from the contract on each call.

---

#### Description

- The function reads `collateralForMinting[listing.tokenId]` and includes it in `amountToSeller`
- It does not set `collateralForMinting[listing.tokenId] = 0` after reading it
- The listing is already required to be inactive, so there is no other guard preventing repeat calls

```solidity
uint256 collateralToReturn = collateralForMinting[listing.tokenId];
// @audit collateralForMinting is never cleared — can be claimed again on repeat calls
amountToSeller += collateralToReturn;
usdc.safeTransfer(msg.sender, amountToSeller);
```

---

#### Risk

**Likelihood:**
- Requires the seller to deliberately call the function twice — trivially exploitable by any seller

**Impact:**
- Each repeat call drains `collateralToReturn` (e.g. 20 USDC) from the general contract balance
- These funds belong to other sellers or minters and will cause their transactions to revert

---

#### Proof of Concept

The lack of a zero-out means the collateral mapping entry persists indefinitely after the first withdrawal. Because the function only checks that the listing is inactive (which it remains after the first call), there is nothing preventing the seller from calling it again and again, each time receiving the full collateral amount from the contract's shared USDC balance.

```solidity
// Listing was sold — it is now inactive
// lockAmount = 20 USDC

dealers.collectUsdcFromSelling(listingId);
// Seller receives: (price - fees) + 20 USDC collateral ✓
// collateralForMinting[tokenId] is still 20e6

dealers.collectUsdcFromSelling(listingId);
// Seller receives: (price - fees) + 20 USDC again — collateral double-drained ✗

dealers.collectUsdcFromSelling(listingId);
// Continues indefinitely until contract balance is exhausted
```

---

#### Recommended Mitigation

Zero out `collateralForMinting` before the transfer, following the CEI pattern. Reading the value first and then clearing it ensures the amount is captured correctly before the storage slot is wiped, while preventing any subsequent call from reading a non-zero value.

```diff
  uint256 collateralToReturn = collateralForMinting[listing.tokenId];
+ collateralForMinting[listing.tokenId] = 0; // clear before transfer to prevent re-entry and repeat claims
  totalFeesCollected += fees;
  amountToSeller += collateralToReturn;
  usdc.safeTransfer(msg.sender, amountToSeller);
```

---

### [M-5] Raw `transferFrom` Used Instead of `safeTransferFrom` in `mintNft` and `buy`

**Impact**: Medium | **Likelihood**: Low
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

`SafeERC20` is imported and used correctly in some functions but inconsistently omitted in `mintNft` and `buy`, which use raw `transferFrom`. Tokens that do not return a boolean will cause silent failures in these two functions.

---

#### Description

- `cancelListing`, `collectUsdcFromSelling`, and `withdrawFees` correctly use `usdc.safeTransfer`
- `mintNft` uses `usdc.transferFrom(...)` inside a `require` — fails silently for non-standard ERC20s
- `buy` assigns `transferFrom` result to a `bool` and checks it — same issue, inconsistent with the rest of the contract

```solidity
// mintNft — raw transferFrom
// @audit should use safeTransferFrom for consistency and safety
require(usdc.transferFrom(msg.sender, address(this), lockAmount), "USDC transfer failed");

// buy — raw transferFrom
bool success = usdc.transferFrom(msg.sender, address(this), listing.price);
require(success, "USDC transfer failed");
```

---

#### Risk

**Likelihood:**
- Only triggered if `usdc` is ever pointed at or replaced with a non-standard ERC20 — low for USDC specifically but a footgun for future maintainers

**Impact:**
- Silent failure or unexpected revert depending on the non-standard token's `transferFrom` implementation
- Inconsistency increases audit complexity and maintenance risk

---

#### Proof of Concept

Some ERC20 tokens — particularly older ones deployed before the standard was finalised — do not return a boolean from `transferFrom`. When called via the raw `IERC20` interface, the ABI decoder attempts to read a `bool` from empty return data. Depending on the compiler and token, this either silently decodes as `false` (causing a misleading revert) or produces undefined behavior. `SafeERC20.safeTransferFrom` handles this by checking for empty return data and treating it as success, which is the correct behaviour.

```solidity
// Token with no return value on transferFrom (e.g. older USDT-style tokens)
// usdc.transferFrom(...) returns nothing
// require() tries to decode the return value as bool → false or revert
// The transfer may have succeeded on-chain but the contract treats it as failed
```

---

#### Recommended Mitigation

Replace both raw `transferFrom` calls with `safeTransferFrom` from the `SafeERC20` library, which is already imported and available. This handles non-standard return values gracefully and makes the transfer behaviour consistent across every function in the contract.

```diff
  // mintNft
- require(usdc.transferFrom(msg.sender, address(this), lockAmount), "USDC transfer failed");
+ usdc.safeTransferFrom(msg.sender, address(this), lockAmount);

  // buy
- bool success = usdc.transferFrom(msg.sender, address(this), listing.price);
- require(success, "USDC transfer failed");
+ usdc.safeTransferFrom(msg.sender, address(this), listing.price);
```

---

## Low Severity

---

### [L-1] Floating Pragma Allows Compilation with Unintended Compiler Versions

**Impact**: Low | **Likelihood**: Low
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

Using `^0.8.34` permits compilation with any `0.8.x` version at or above `0.8.34`, meaning different environments may produce different bytecode from the same source file.

---

#### Description

- A floating pragma does not guarantee reproducible builds across toolchains and CI environments
- Compiler versions introduce bug fixes and behaviour changes that can affect contract behaviour subtly

```solidity
// @audit floating pragma — allows any 0.8.x >= 0.8.34
pragma solidity ^0.8.34;
```

---

#### Risk

**Likelihood:**
- Only relevant when building in environments without a pinned compiler version

**Impact:**
- Compiled bytecode may differ from what was tested and audited
- Subtle behavioural differences may be introduced by newer compiler versions

---

#### Recommended Mitigation

Pin the pragma to an exact version. This guarantees that every environment — local development, CI, and production deployment — produces identical bytecode from the same source, which is a prerequisite for meaningful audit reproducibility.

```diff
- pragma solidity ^0.8.34;
+ pragma solidity 0.8.34;
```

---

### [L-2] Constructor Parameter `_symbol` Shadows `ERC721._symbol`

**Impact**: Low | **Likelihood**: Low
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

The constructor parameter `_symbol` shares its name with the private `_symbol` state variable inherited from OpenZeppelin's `ERC721` contract, creating a shadowing warning that can confuse developers and static analysis tools.

---

#### Description

- OpenZeppelin's `ERC721` declares `string private _symbol`
- The constructor parameter `_symbol` shadows this variable within the constructor scope
- While the parameter is correctly forwarded to the `ERC721` parent constructor, the shadowing increases confusion risk in future modifications

```solidity
constructor(
    ...
    string memory _symbol, // @audit shadows ERC721._symbol
    ...
) ERC721(_collectionName, _symbol) {
    tokenSymbol = _symbol;
}
```

---

#### Risk

**Likelihood:**
- Triggered any time a developer reads or modifies the constructor — purely a code clarity issue

**Impact:**
- No runtime impact currently
- Future developers may accidentally reference the wrong variable

---

#### Recommended Mitigation

Rename the constructor parameter to something that does not clash with the inherited variable name. Using `_tokenSymbol` makes the intent clear and eliminates the shadowing warning from compilers and static analysers without any functional change.

```diff
  constructor(
      ...
-     string memory _symbol,
+     string memory _tokenSymbol,
      ...
- ) ERC721(_collectionName, _symbol) {
+ ) ERC721(_collectionName, _tokenSymbol) {
-     tokenSymbol = _symbol;
+     tokenSymbol = _tokenSymbol;
  }
```

---

### [L-3] Token ID Counter Increments Before Minting — Token ID 0 Is Permanently Skipped

**Impact**: Low | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

`tokenIdCounter` starts at 0 and is incremented before `_safeMint` is called, so the first minted NFT receives token ID 1. Token ID 0 is never minted, creating a permanent gap that breaks off-chain tooling assuming 0-based token IDs.

---

#### Description

- `tokenIdCounter` initialises to 0
- `tokenIdCounter++` runs before `_safeMint`, so the first NFT receives token ID 1
- `collateralForMinting[0]` is never set, but lookups at slot 0 will return 0 silently
- `MAX_SUPPLY = 1000` means only IDs 1–1000 exist, not 0–999 as typically expected

```solidity
tokenIdCounter++; // @audit increments before mint — token ID 0 is permanently skipped
collateralForMinting[tokenIdCounter] = lockAmount;
_safeMint(msg.sender, tokenIdCounter);
```

---

#### Risk

**Likelihood:**
- Happens on the very first mint and carries through for every subsequent one — systematic

**Impact:**
- Off-chain tooling, metadata servers, and frontends expecting token ID 0 will break
- Effective supply is IDs 1–1000 instead of 0–999

---

#### Recommended Mitigation

Move the increment to after the mint call. This way the first mint receives token ID 0, subsequent mints receive 1, 2, 3 and so on, and `collateralForMinting` is populated with the correct ID before `_safeMint` is called. The semantics of the counter remain the same — it just reflects the last minted ID rather than the next one.

```diff
- tokenIdCounter++;
  collateralForMinting[tokenIdCounter] = lockAmount;
  _safeMint(msg.sender, tokenIdCounter);
+ tokenIdCounter++;
```

---

### [L-4] Multiple State-Changing Functions Emit No Events

**Impact**: Low | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

`revealCollection`, `whitelistWallet`, `removeWhitelistedWallet`, `collectUsdcFromSelling`, and `mintNft` all modify state without emitting events, making it impossible to track these changes off-chain without polling storage.

---

#### Description

- `revealCollection` sets `isCollectionRevealed = true` with no event
- `whitelistWallet` and `removeWhitelistedWallet` modify `whitelistedUsers` with no event
- `mintNft` mints an NFT and locks collateral without a custom application-level event
- `collectUsdcFromSelling` transfers significant funds without an event

```solidity
// @audit no event emitted for a critical state change
function revealCollection() external onlyOwner {
    isCollectionRevealed = true;
}

// @audit no event emitted
function whitelistWallet(address _wallet) external onlyOwner {
    whitelistedUsers[_wallet] = true;
}
```

---

#### Risk

**Likelihood:**
- Every call to these functions produces no trackable event — systematic gap across the contract

**Impact:**
- Off-chain monitoring, indexers, and frontends cannot observe critical state changes
- Audit trails and incident response are significantly impaired

---

#### Recommended Mitigation

Define and emit a dedicated event in each affected function. Events should be indexed by the most query-relevant parameter (address for whitelist changes, token ID for mints) so that off-chain tooling can efficiently filter them. The example below shows the pattern for the two most commonly called owner functions; the same approach should be applied to `mintNft` and `collectUsdcFromSelling`.

```diff
+ event NFT_Dealers_CollectionRevealed();
+ event NFT_Dealers_WalletWhitelisted(address indexed wallet);
+ event NFT_Dealers_WalletRemoved(address indexed wallet);
+ event NFT_Dealers_Minted(address indexed minter, uint256 indexed tokenId, uint256 collateral);
+ event NFT_Dealers_ProceedsCollected(address indexed seller, uint256 indexed listingId, uint256 amount);

  function revealCollection() external onlyOwner {
      isCollectionRevealed = true;
+     emit NFT_Dealers_CollectionRevealed();
  }

  function whitelistWallet(address _wallet) external onlyOwner {
      whitelistedUsers[_wallet] = true;
+     emit NFT_Dealers_WalletWhitelisted(_wallet);
  }

  function removeWhitelistedWallet(address _wallet) external onlyOwner {
      whitelistedUsers[_wallet] = false;
+     emit NFT_Dealers_WalletRemoved(_wallet);
  }
```

---

### [L-5] `updatePrice` Reads `oldPrice` Before Checking Listing Is Active

**Impact**: Low | **Likelihood**: Low
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

In `updatePrice`, the old price is cached from memory before the `isActive` guard runs. The function reverts correctly either way, but the ordering violates defensive coding practices and the CEI pattern, and could emit a stale price in future refactors.

---

#### Description

- `oldPrice` is read before the `isActive` guard, meaning unnecessary computation occurs for inactive listings
- If logic is reordered in future, a stale price value could be emitted in the `NFT_Dealers_Price_Updated` event

```solidity
Listing memory listing = s_listings[_listingId];
uint256 oldPrice = listing.price;              // @audit read before active check
if (!listing.isActive) revert ListingNotActive(_listingId);
```

---

#### Risk

**Likelihood:**
- Only relevant if code is refactored — no current runtime impact

**Impact:**
- Stale price could be emitted in `NFT_Dealers_Price_Updated` if the guard is removed or reordered in future

---

#### Recommended Mitigation

Reorder the operations so the `isActive` check runs first and `oldPrice` is only read after the listing is confirmed to be active. Reading directly from storage rather than a cached memory struct also avoids the possibility of a stale memory value being used if the struct is reused elsewhere in the function.

```diff
  function updatePrice(uint256 _listingId, uint32 _newPrice) external onlySeller(_listingId) {
-     Listing memory listing = s_listings[_listingId];
-     uint256 oldPrice = listing.price;
-     if (!listing.isActive) revert ListingNotActive(_listingId);
+     if (!s_listings[_listingId].isActive) revert ListingNotActive(_listingId);
+     uint256 oldPrice = s_listings[_listingId].price;
      require(_newPrice > 0, "Price must be greater than 0");
      s_listings[_listingId].price = _newPrice;
      emit NFT_Dealers_Price_Updated(_listingId, oldPrice, _newPrice);
  }
```

---

### [L-6] Precision Loss in Fee Calculation Due to Integer Division Truncation

**Impact**: Low | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

`_calculateFees` uses integer division which always truncates the decimal portion of the result. Sellers can exploit fee tier thresholds by pricing just below them to consistently pay lower fees than intended.

---

#### Description

- `(_price * FEE_BPS) / MAX_BPS` always rounds down, so the protocol collects slightly less than the true percentage on every transaction
- At high volume, this truncation accumulates into meaningful revenue loss
- Sellers pricing just under `LOW_FEE_THRESHOLD` or `MID_FEE_THRESHOLD` pay the lower tier fee with a further truncation advantage

```solidity
// @audit integer division truncates — fee is always slightly less than the true percentage
return (_price * LOW_FEE_BPS) / MAX_BPS;
```

---

#### Risk

**Likelihood:**
- Affects every fee calculation — systematic across all sales

**Impact:**
- Consistent under-collection of fees; exploitable at thresholds for structured price manipulation

---

#### Proof of Concept

The example below shows the truncation on a price just below the low fee threshold. The difference per transaction is small, but a seller who consistently prices at this value pays slightly less than the intended 1% fee every time. At scale across many transactions the accumulated underpayment becomes significant.

```solidity
// Price = 999_999 units (just under LOW_FEE_THRESHOLD of 1_000_000_000)
// True 1% fee: 999_999 * 100 / 10_000 = 9999.99
// Solidity result: 9999 (0.99 truncated — lost on every such transaction)
uint256 fee = _calculateFees(999_999); // returns 9999, not 10000
```

---

#### Recommended Mitigation

Use ceiling division instead of floor division for fee calculation. Adding `MAX_BPS - 1` to the numerator before dividing ensures the result always rounds up, meaning the protocol collects at least the correct percentage rather than slightly less. This is a standard pattern for fee rounding in Solidity and does not require any external library.

```diff
  function _calculateFees(uint256 _price) internal pure returns (uint256) {
      if (_price <= LOW_FEE_THRESHOLD) {
-         return (_price * LOW_FEE_BPS) / MAX_BPS;
+         return (_price * LOW_FEE_BPS + MAX_BPS - 1) / MAX_BPS;
      } else if (_price <= MID_FEE_THRESHOLD) {
-         return (_price * MID_FEE_BPS) / MAX_BPS;
+         return (_price * MID_FEE_BPS + MAX_BPS - 1) / MAX_BPS;
      }
-     return (_price * HIGH_FEE_BPS) / MAX_BPS;
+     return (_price * HIGH_FEE_BPS + MAX_BPS - 1) / MAX_BPS;
  }
```

---

### [L-7] `calculateFees` Public Wrapper Must Be Removed Before Production Deployment

**Impact**: Low | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Root + Impact

A `calculateFees` function is exposed publicly for testing purposes with a comment explicitly stating it must be removed before production. Leaving it in reveals fee tier logic and widens the attack surface unnecessarily.

---

#### Description

- The function serves no user-facing purpose and is a testing artifact
- It reveals the exact fee tier thresholds to any caller, enabling structured pricing to game fees
- The comment in the code itself acknowledges this risk

```solidity
function calculateFees(uint256 price) external pure returns (uint256) {
    // must be removed before production deployment, as it can be gamed
    // by malicious actors to calculate the fees for a given price
    return _calculateFees(price);
}
```

---

#### Risk

**Likelihood:**
- Discoverable by any actor reading the ABI or contract source

**Impact:**
- Enables actors to calculate exact prices that minimise fees at tier boundaries
- Increases deployed bytecode size unnecessarily

---

#### Recommended Mitigation

Delete the public wrapper entirely before deployment. The `_calculateFees` function is `internal` and therefore inaccessible to external callers, which is the desired production state. For test coverage, Foundry provides mechanisms to call internal functions directly from test files without needing a public wrapper — for example, inheriting the contract under test or using `vm.prank` with a harness contract that exposes the internal for testing only.

```diff
- function calculateFees(uint256 price) external pure returns (uint256) {
-     return _calculateFees(price);
- }
```

---

## Informational

---

### [I-1] State Variables Set Only in Constructor Should Be Declared `immutable`

**Impact**: Informational | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Description

- `owner`, `collectionImage`, `collectionName`, and `tokenSymbol` are all assigned in the constructor and never modified afterward
- Declaring them `immutable` removes their storage slots, saving gas on deployment and on every read
- It also signals to readers that these values are fixed for the lifetime of the contract

```solidity
address public owner;           // @audit should be immutable
string private collectionImage; // @audit should be immutable
string public collectionName;   // @audit should be immutable
string public tokenSymbol;      // @audit should be immutable
```

#### Recommended Mitigation

Marking these variables `immutable` bakes their values directly into the contract bytecode at deployment, eliminating the storage reads that would otherwise occur on every access. This is a zero-risk change since none of these variables are written to after construction.

```diff
- address public owner;
- string private collectionImage;
- string public collectionName;
- string public tokenSymbol;
+ address public immutable owner;
+ string private immutable collectionImage;
+ string public immutable collectionName;
+ string public immutable tokenSymbol;
```

---

### [I-2] Explicit Boolean Comparison to `false` Should Use Negation Operator

**Impact**: Informational | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Description

- Comparing a boolean to `false` explicitly is redundant and reduces readability
- The negation operator `!` is idiomatic Solidity

```solidity
// @audit verbose boolean comparison
require(s_listings[_tokenId].isActive == false, "NFT is already listed");
```

#### Recommended Mitigation

Replace the explicit comparison with the `!` negation operator. This is the conventional Solidity style, produces identical bytecode, and is immediately readable without requiring the reader to parse a comparison expression.

```diff
- require(s_listings[_tokenId].isActive == false, "NFT is already listed");
+ require(!s_listings[_tokenId].isActive, "NFT is already listed");
```

---

### [I-3] `mintNft` Contains an Impossible Zero Address Check for `msg.sender`

**Impact**: Informational | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Description

- The EVM guarantees that `msg.sender` is never `address(0)` for externally originated transactions
- This check is dead code that wastes a small amount of gas on every mint call

```solidity
// @audit msg.sender can never be address(0) — dead code
if (msg.sender == address(0)) revert InvalidAddress();
```

#### Recommended Mitigation

Remove the check entirely. It can never trigger and provides no protection. Any developer reading it may be confused into thinking there is a real scenario where `msg.sender` could be zero, which is not the case for external transactions in the EVM.

```diff
- if (msg.sender == address(0)) revert InvalidAddress();
```

---

### [I-4] `metadataFrozen` Is Declared but Never Set or Checked — Freeze Feature Is Incomplete

**Impact**: Informational | **Likelihood**: High
**Scope**: `../NFTDealers.sol`

---

#### Description

- `metadataFrozen` is declared as a public state variable initialising to `false`
- There is no function to set it to `true` and no function that checks it before allowing metadata changes
- The freeze feature is declared but never implemented, making the variable dead state

```solidity
// @audit declared but never set to true or checked anywhere in the contract
bool public metadataFrozen;
```

#### Recommended Mitigation

Either implement the freeze feature fully or remove the variable. Leaving dead state in the contract increases deployment cost, creates confusion for readers, and may cause false assumptions about what protections are in place. If the freeze is intended for a future version, it should be removed now and added when the full implementation is ready.

If implementing: add a `freezeMetadata()` function that sets the flag, gate `_baseURI` behind it, and emit an event so the freeze is observable off-chain.

```diff
+ event NFT_Dealers_MetadataFrozen();

+ function freezeMetadata() external onlyOwner {
+     metadataFrozen = true;
+     emit NFT_Dealers_MetadataFrozen();
+ }

  function _baseURI() internal view override returns (string memory) {
+     require(!metadataFrozen, "Metadata is frozen");
      return collectionImage;
  }
```

If removing:

```diff
- bool public metadataFrozen;
```

---

### [I-5] `MAX_BPS` Literal Should Use Scientific Notation for Consistency

**Impact**: Informational | **Likelihood**: Low
**Scope**: `../NFTDealers.sol`

---

#### Description

- Other large literals in the contract use scientific notation (`1000e6`, `10_000e6`, `1e6`)
- `MAX_BPS = 10_000` is inconsistent with this style

```solidity
// @audit inconsistent with other large literals in the contract
uint32 private constant MAX_BPS = 10_000;
```

#### Recommended Mitigation

Replace the underscore-separated literal with `1e4` to match the scientific notation style used throughout the rest of the constants. This is a cosmetic change with no runtime impact, but consistent literal formatting reduces cognitive overhead when scanning constants.

```diff
- uint32 private constant MAX_BPS = 10_000;
+ uint32 private constant MAX_BPS = 1e4;
```