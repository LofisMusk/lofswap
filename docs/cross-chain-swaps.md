# Cross-Chain Atomic Swaps (HTLC)

LofSwap settles cross-chain trades — `USDC (Ethereum) -> USDC (Solana)`,
`LFS -> USDC`, and so on — with hashed timelock contracts (HTLC). There is no
bridge, no wrapped asset and no operator that could run away with the funds:
either both legs of a trade settle, or both refund.

This document describes the leg that lives on LofSwap. The counter-leg lives on
the foreign chain and must use the *same* SHA-256 hashlock.

## Why an HTLC and not a bridge

A bridge holds custody: it locks the asset on chain A and mints a claim on
chain B, so its validator set (or multisig) can freeze or steal the deposits.
An HTLC swap never transfers custody to a third party. The two counterparties
lock their own funds on their own chains under one shared secret:

* whoever reveals the secret to take their side automatically hands the
  counterparty everything they need to take the other side;
* if nobody reveals it, both locks expire and both sides refund.

The only cost of a failed swap is the timelock wait and the fees.

## Protocol

```text
Alice holds USDC on Ethereum.   Bob holds USDC on Solana.
Alice wants Bob's SOL-side USDC; the LFS leg below works identically for
LFS <-> anything, with LofSwap always holding the LFS side of the trade.

1. Alice:  secret S (32 random bytes), hashlock H = sha256(S)
2. Alice:  locks her asset under H with timelock T1
3. Bob:    verifies H and Alice's lock, then locks his asset under the SAME H
           with timelock T2, where T2 << T1
4. Alice:  claims Bob's leg -> this publishes S
5. Bob:    reads S from the chain Alice claimed on and claims Alice's leg
6. If step 4 never happens, both locks expire: Bob refunds after T2,
   Alice after T1.
```

**Timelock ordering is the safety rule of the whole protocol.** The party that
moves *second* must have the *shorter* timelock. If Bob's lock expired first
while Alice could still claim it, Alice could wait out Bob's refund window and
then claim, taking both legs. LofSwap's wallet prints a reminder of this
whenever you lock against somebody else's hashlock; the recommended ratio is
`T1 = 2 * T2` (for example 24h and 12h).

## Transactions on LofSwap

Three transaction kinds implement the local leg (`version 4`, wire names
`swaplock`, `swapclaim`, `swaprefund`):

| Kind          | From         | To          | Authorised by | Effect |
|---------------|--------------|-------------|---------------|--------|
| `SwapLock`    | maker        | escrow      | maker         | moves `amount` into the escrow |
| `SwapClaim`   | escrow       | recipient   | recipient     | pays out, publishes the secret |
| `SwapRefund`  | escrow       | maker       | maker         | pays back after the timelock |

### Escrow addresses

The locked coins sit at a normal-looking `LFS...` address that **nobody has a
private key for**:

```text
swap_id = sha256("lofswap-swap-v1|chain_id|maker|recipient|amount|hashlock|timelock|nonce|foreign_digest")
escrow  = LFS + base58(sha256("lofswap-swap-v1-escrow|" + swap_id)[0..20])
```

Because the id commits to every term *and* to the maker's nonce, it is unique,
it is known before the lock is signed, and a lock whose `to` field does not
equal the escrow of its own terms is rejected. Balances, explorers and the
`/balance/{address}` endpoint show escrows like any other account, so locked
funds are always publicly auditable.

### Validation rules

`SwapLock`
* transaction version >= 4 and a swap payload is present;
* `hashlock` is a 64-character lowercase SHA-256 digest;
* `recipient` is a valid `LFS` address and is not the maker;
* `timelock` is between 30 minutes and 30 days after the transaction
  timestamp, and is still in the future at the current median time past;
* `swap_id` matches the commitment above and `to` is its escrow;
* the maker pays `amount + fee`, with the usual nonce, balance and signature
  checks;
* the swap id has never been used before;
* `amount` is greater than the settlement fee — a lock that could not pay for
  its own claim or refund would freeze the coins for good.

`SwapClaim`
* the swap exists and is still open;
* `hashlock` and `timelock` in the payload repeat the locked terms, so a
  settlement can never be replayed against a different swap;
* `secret` is 32 bytes of hex and `sha256(secret) == hashlock`;
* the transaction pays the recorded recipient and is signed by that
  recipient's key — knowing the secret is *not* enough to redirect the payout
  or to inflate the fee;
* median time past is still below the timelock;
* `amount + fee == locked amount`: the escrow is always drained completely, so
  no dust remains and settlements are never free to relay.

`SwapRefund`
* the swap exists and is still open, the payload repeats the locked terms;
* the transaction pays the maker and is signed by the maker's key;
* median time past has reached the timelock;
* the escrow is drained completely, as above.

### Time is measured with median time past

Every timelock comparison uses the median timestamp of the last 11 blocks, not
the timestamp of the block carrying the settlement. A miner therefore cannot
push the clock forward to grab an early refund, nor stall a claim, without
moving the median of the whole recent chain.

## The foreign leg

A lock may commit to the counter-leg it belongs to:

```json
"foreign": {
  "chain": "eip155:1",
  "asset": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "amount": "25000000",
  "beneficiary": "0x1111111111111111111111111111111111111111",
  "htlc_ref": "0x…contract or tx…"
}
```

LofSwap nodes do **not** verify these fields — no node reads Ethereum or
Solana state — but they are folded into the swap id and covered by the maker's
signature, so the advertised terms of a trade are public and immutable. Wallets
and explorers can show exactly which foreign HTLC a LofSwap escrow belongs to,
and a maker cannot later claim they promised something else.

The foreign HTLC must hash the same 32 raw secret bytes with SHA-256. Both
implementations live in this repository:

* [`contracts/evm/`](../contracts/evm) — `LofSwapHTLC.sol` for Ethereum, BNB
  Chain, Polygon, Arbitrum, Base and any other EVM chain; escrows the native
  coin or any ERC-20 (USDC, USDT, …) and hashes with
  `sha256(abi.encodePacked(secret))`, never `keccak256`;
* [`contracts/solana/`](../contracts/solana) — a native Solana program for SOL
  and SPL tokens, hashing with the SHA-256 syscall.

[`contracts/README.md`](../contracts/README.md) walks through a full
`USDC (Ethereum) -> USDC (Solana)` trade and lists the deployment steps.

## Wallet commands

```bash
swap-secret                       # draw secret S and hashlock H, stored locally
swap-lock --to <LFS_ADDRESS> --amount <n> [--hours 24] \
          [--hashlock <hex>] \
          [--foreign <chain>,<asset>,<base-unit-amount>,<beneficiary>[,<ref>]]
swap-claim <swap_id> [secret]     # publishes the secret, pays the recipient
swap-refund <swap_id>             # only after the timelock expired
swap-show <swap_id|escrow>
swap-list [address|open]
```

`swap-lock` without `--hashlock` starts a swap: it draws a secret, saves it to
`wallet-cache/swap_secrets.json` and prints the hashlock to hand to the
counterparty. `swap-lock --hashlock <H>` answers somebody else's swap — use a
timelock clearly shorter than theirs.

> Back up `wallet-cache/swap_secrets.json` while a swap is open. Losing it
> before you claim means losing that leg; the counterparty still refunds
> normally after their timelock.

## Node and explorer endpoints

Node (TCP request paths):

* `/swap/{swap_id|escrow}` — one swap record
* `/swaps` — all swaps (newest first, max 200)
* `/swaps/open` — only unsettled swaps
* `/swaps/address/{address}` — swaps where the address is maker, recipient or escrow

Node CLI: `print-swaps`.

Explorer API:

* `GET /api/swaps?status=open&address=LFS…`
* `GET /api/swap/:id`

## Consensus compatibility

Swap transactions are a hard fork: a node that predates them rejects any block
containing one. `SWAP_ACTIVATION_HEIGHT` in `node-cli/src/swap.rs` is the
height from which they are accepted (`0` — active from genesis on the current
testnet). When forking an already running network, set it to a height far
enough ahead for every node operator to upgrade first, and ship that value to
all nodes before the fork.

Transactions without a swap payload serialize byte-for-byte as they did before
this feature, so existing block hashes and signatures stay valid.

## Limits

* Do not send ordinary transfers to an escrow address. Settlements pay out
  exactly the locked amount, so anything sent on top stays there forever.

* LofSwap only ever holds the LFS leg. An `USDC(ETH) -> USDC(SOL)` trade needs
  HTLC contracts deployed on both foreign chains; LofSwap is the coordination
  and settlement record, plus the place a market maker's LFS collateral can be
  locked.
* Nothing here verifies the foreign leg. A counterparty can always simply not
  lock their side — the cost of that is the timelock wait, never the funds.
* There is no on-chain order book yet: counterparties find each other
  off-chain and then commit their terms with `swap-lock`.
