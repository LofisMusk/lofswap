# LofSwap foreign legs

A LofSwap cross-chain trade has two legs. The LofSwap leg lives in the chain
itself (`SwapLock` / `SwapClaim` / `SwapRefund`, see
[`../docs/cross-chain-swaps.md`](../docs/cross-chain-swaps.md)). The foreign
leg lives here:

| Directory | Chains | What it is |
|-----------|--------|------------|
| [`evm/`](./evm) | Ethereum, BNB Chain, Polygon, Arbitrum, Base, opBNB — any EVM chain | `LofSwapHTLC.sol`, an escrow for the native coin and for any ERC-20 (USDC, USDT, …) |
| [`solana/`](./solana) | Solana | a native Solana program, escrow for SOL and any SPL token |

Both are hashed timelock escrows. Neither has an admin, an owner, a pause
switch or an upgrade key: once funds are locked, the only two ways out are the
secret (before the timelock) or the refund (after it).

## One secret, three chains

Every leg hashes the **same 32 raw bytes with SHA-256**:

```text
LofSwap   sha256(secret)                    blockchain-core::swap::hashlock_for_secret_hex
EVM       sha256(abi.encodePacked(secret))  LofSwapHTLC.hashlockFor
Solana    sha256(secret)                    swap_id::hashlock_for
```

The three test-suites are pinned to the same vector, so a change on one chain
breaks the build rather than a live trade:

```text
secret   = 9a9a9a…9a  (32 bytes)
hashlock = 8b9d52fd75ae21d2b827872bd084d762b24fb716dc87974668ecafcfe55df678
```

Do **not** substitute keccak256 on the EVM side. It is the cheaper hash there,
but it would stop the legs from unlocking each other.

## Worked example: USDC (Ethereum) → USDC (Solana)

Alice holds USDC on Ethereum and wants USDC on Solana. Bob has the mirror
position. Nobody has to trust anybody.

```text
1. Alice draws a secret S and publishes only H = sha256(S)
     lofswap wallet:  swap-secret

2. Alice locks 25 USDC on Ethereum for Bob, timelock T1 = now + 24h
     LofSwapHTLC.open(bob, USDC, 25e6, H, T1, counterpartyRef)

3. Bob checks Alice's escrow on Ethereum (amount, recipient, H, T1) and locks
   25 USDC on Solana for Alice with T2 = now + 12h — half of T1
     lofswap-htlc-solana: Lock { asset: SplToken, recipient: alice, .., H, T2 }

4. Alice claims on Solana with S. That transaction publishes S on chain.
     Claim { secret: S }

5. Bob reads S from Solana and claims on Ethereum before T1.
     LofSwapHTLC.claim(id, S)

If step 4 never happens: Bob refunds after T2, Alice after T1. Nothing is lost
but time and gas.
```

Replace either leg with the LofSwap chain (`swap-lock` / `swap-claim` /
`swap-refund`) to trade LFS against a foreign asset; the choreography is
identical.

### The one rule that keeps this safe

**The party that moves second must have the shorter timelock**, and the gap
has to be comfortably larger than the settlement time of the slower chain. If
Bob's leg expired first while Alice could still claim it, Alice could sit out
Bob's refund window and then take both legs. Halving is the usual choice:
`T1 = 24h`, `T2 = 12h`.

Both escrows enforce a floor of 10 minutes and a ceiling of 30 days; the
LofSwap chain enforces 30 minutes to 30 days on its own leg.

## Linking the legs on chain

Both escrows carry a `counterparty_ref` / `counterpartyRef` field: put the
other leg's id in it (for a LofSwap leg, its `swap_id`). It is not verified —
no chain reads another chain here — but it makes the pair auditable from
either side, and it is covered by the same signature as the rest of the terms.

## Deployment

### EVM

```bash
cd contracts/evm
npm install
npm test                       # real EVM execution, no node or testnet needed
```

The contract compiles with solc 0.8.28 targeting the **paris** EVM version, so
the same bytecode deploys on chains that have not enabled Shanghai/PUSH0.
Deploy it with whatever you already use (Foundry, Hardhat, Remix); it has no
constructor arguments, so the same address can be reached with CREATE2 on
every chain if you want matching addresses.

Chain ids are folded into every swap id, so one deployment can never be
replayed against another chain.

### Solana

```bash
cd contracts/solana
cargo test                     # unit tests, host toolchain
cargo build-sbf                # on-chain artefact (needs the Solana toolchain)
solana program deploy target/deploy/lofswap_htlc_solana.so
```

For an SPL swap the client creates the escrow token account (an ATA owned by
the swap PDA) in the same transaction as `Lock`; the program checks its mint
and owner before it accepts the deposit. The swap PDA is
`["lofswap-htlc", swap_id]`, and `swap_id` is derived from the full terms, so
a counterparty can recompute it and refuse a swap whose escrow disagrees with
what they were promised.

`Close` returns the rent of a settled swap to its maker, but only once the
timelock has passed — until then the revealed secret stays readable on chain
for the counterparty.

## Status

These contracts are **new and unaudited**. The EVM contract is exercised by a
suite that runs the real EVM (`npm test`, 11 cases: happy path, wrong secret,
double settlement, both sides of the timelock, ERC-20, fee-on-transfer tokens,
tokens that fail silently). The Solana program's pure logic — swap id
derivation, hashlock parity, state layout, instruction encoding — is unit
tested, but it has **not** been run against a validator here, because this
environment has no Solana toolchain.

Before touching real money: deploy to Sepolia / BNB testnet / Solana devnet,
run a full swap in both directions, and have the code reviewed. Start with
amounts you are willing to lose.
