'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Chainlet } = require('../scripts/harness');

const SOURCES = ['src/LofSwapHTLC.sol', 'test/mocks.sol'];
const HOUR = 3600;

/// The very secret used by the LofSwap node test-suite, with the hashlock the
/// Rust implementation produces for it. If the two ever diverge, the legs of a
/// swap stop unlocking each other — so this vector is pinned here on purpose.
const SECRET = '0x' + '9a'.repeat(32);
const HASHLOCK = '0x8b9d52fd75ae21d2b827872bd084d762b24fb716dc87974668ecafcfe55df678';

async function setup() {
  const chain = await Chainlet.create(SOURCES);
  const now = 1_800_000_000;
  chain.setTimestamp(now);

  const maker = chain.address(0x11);
  const taker = chain.address(0x22);
  const stranger = chain.address(0x33);
  for (const who of [maker, taker, stranger]) {
    await chain.fund(who, 10n ** 20n);
  }

  const htlc = await chain.deploy('LofSwapHTLC', maker);
  return { chain, now, maker, taker, stranger, htlc };
}

async function openNative(ctx, { amount = 10n ** 18n, timelock, recipient } = {}) {
  const { chain, now, maker, taker, htlc } = ctx;
  const { logs } = await chain.call(
    htlc,
    maker,
    'open',
    [
      (recipient ?? taker).toString(),
      '0x' + '00'.repeat(20),
      amount,
      HASHLOCK,
      BigInt(timelock ?? now + 24 * HOUR),
      '0x' + '11'.repeat(32),
    ],
    amount,
  );
  const opened = logs.find((l) => l.name === 'Opened');
  assert.ok(opened, 'Opened event');
  return opened.args.id;
}

test('the pinned hashlock matches sha256 of the raw secret bytes', async () => {
  const { chain, htlc } = await setup();
  const digest = '0x' + crypto.createHash('sha256')
    .update(Buffer.from(SECRET.slice(2), 'hex'))
    .digest('hex');
  assert.equal(digest, HASHLOCK, 'node sha256 must match the pinned LofSwap vector');
  const { result } = await chain.call(htlc, chain.address(0x11), 'hashlockFor', [SECRET]);
  assert.equal(result[0], HASHLOCK, 'the contract must hash the secret the same way');
});

test('claim pays the recipient and publishes the secret', async () => {
  const ctx = await setup();
  const { chain, taker, stranger, htlc } = ctx;
  const amount = 10n ** 18n;
  const id = await openNative(ctx, { amount });

  const before = await chain.balance(taker);
  // Anybody may push the secret; the money still goes to the recipient.
  const { logs } = await chain.call(htlc, stranger, 'claim', [id, SECRET]);
  const claimed = logs.find((l) => l.name === 'Claimed');
  assert.equal(claimed.args.secret, SECRET, 'the secret is published for the other leg');
  assert.equal(await chain.balance(taker), before + amount);

  const { result } = await chain.call(htlc, taker, 'getSwap', [id]);
  assert.equal(Number(result[0].state), 2, 'state == Claimed');
});

test('a wrong secret cannot open the escrow', async () => {
  const ctx = await setup();
  const id = await openNative(ctx);
  await assert.rejects(
    ctx.chain.call(ctx.htlc, ctx.taker, 'claim', [id, '0x' + 'ab'.repeat(32)]),
    /BadSecret/,
  );
});

test('the same escrow cannot be drained twice', async () => {
  const ctx = await setup();
  const id = await openNative(ctx);
  await ctx.chain.call(ctx.htlc, ctx.taker, 'claim', [id, SECRET]);
  await assert.rejects(ctx.chain.call(ctx.htlc, ctx.taker, 'claim', [id, SECRET]), /SwapNotOpen/);
  await assert.rejects(ctx.chain.call(ctx.htlc, ctx.maker, 'refund', [id]), /SwapNotOpen/);
});

test('refund is impossible before the timelock and mandatory after it', async () => {
  const ctx = await setup();
  const { chain, now, maker, htlc } = ctx;
  const amount = 10n ** 18n;
  const id = await openNative(ctx, { amount, timelock: now + 12 * HOUR });

  await assert.rejects(chain.call(htlc, maker, 'refund', [id]), /SwapNotExpired/);

  chain.setTimestamp(now + 12 * HOUR);
  // Once the deadline passes the claim window is shut...
  await assert.rejects(chain.call(htlc, ctx.taker, 'claim', [id, SECRET]), /SwapExpired/);
  // ...and the maker gets the funds back.
  const before = await chain.balance(maker);
  await chain.call(htlc, ctx.stranger, 'refund', [id]);
  assert.equal(await chain.balance(maker), before + amount);
});

test('timelocks outside the allowed window are refused', async () => {
  const ctx = await setup();
  const { chain, now, maker, taker, htlc } = ctx;
  const args = (timelock) => [
    taker.toString(),
    '0x' + '00'.repeat(20),
    10n ** 18n,
    HASHLOCK,
    BigInt(timelock),
    '0x' + '00'.repeat(32),
  ];
  await assert.rejects(
    chain.call(htlc, maker, 'open', args(now + 60), 10n ** 18n),
    /TimelockOutOfRange/,
  );
  await assert.rejects(
    chain.call(htlc, maker, 'open', args(now + 31 * 24 * HOUR), 10n ** 18n),
    /TimelockOutOfRange/,
  );
});

test('a swap cannot pay its own maker, nobody, or zero', async () => {
  const ctx = await setup();
  const { chain, now, maker, taker, htlc } = ctx;
  const native = '0x' + '00'.repeat(20);
  const timelock = BigInt(now + 24 * HOUR);
  await assert.rejects(
    chain.call(htlc, maker, 'open', [maker.toString(), native, 1n, HASHLOCK, timelock, native + '000000000000000000000000'], 1n),
    /InvalidRecipient/,
  );
  await assert.rejects(
    chain.call(htlc, maker, 'open', [taker.toString(), native, 0n, HASHLOCK, timelock, '0x' + '00'.repeat(32)], 0n),
    /InvalidAmount/,
  );
  // Native swaps must be funded with exactly `amount`.
  await assert.rejects(
    chain.call(htlc, maker, 'open', [taker.toString(), native, 10n ** 18n, HASHLOCK, timelock, '0x' + '00'.repeat(32)], 1n),
    /NativeValueMismatch/,
  );
});

test('USDC-style ERC-20 swaps settle end to end', async () => {
  const ctx = await setup();
  const { chain, now, maker, taker, htlc } = ctx;
  const usdc = await chain.deploy('MockERC20', maker);
  const amount = 25_000_000n; // 25 USDC, 6 decimals

  await chain.call(usdc, maker, 'mint', [maker.toString(), amount]);
  await chain.call(usdc, maker, 'approve', [htlc.address.toString(), amount]);

  const { logs } = await chain.call(htlc, maker, 'open', [
    taker.toString(),
    usdc.address.toString(),
    amount,
    HASHLOCK,
    BigInt(now + 12 * HOUR),
    '0x' + '11'.repeat(32),
  ]);
  const id = logs.find((l) => l.name === 'Opened').args.id;

  const escrowed = await chain.call(usdc, maker, 'balanceOf', [htlc.address.toString()]);
  assert.equal(escrowed.result[0], amount, 'the escrow holds the tokens');

  await chain.call(htlc, taker, 'claim', [id, SECRET]);
  const takerBalance = await chain.call(usdc, taker, 'balanceOf', [taker.toString()]);
  assert.equal(takerBalance.result[0], amount);
});

test('fee-on-transfer tokens are escrowed at what actually arrived', async () => {
  const ctx = await setup();
  const { chain, now, maker, taker, htlc } = ctx;
  const token = await chain.deploy('MockFeeERC20', maker);
  const amount = 1_000_000n;

  await chain.call(token, maker, 'mint', [maker.toString(), amount]);
  await chain.call(token, maker, 'approve', [htlc.address.toString(), amount]);
  const { logs } = await chain.call(htlc, maker, 'open', [
    taker.toString(),
    token.address.toString(),
    amount,
    HASHLOCK,
    BigInt(now + 12 * HOUR),
    '0x' + '00'.repeat(32),
  ]);
  const id = logs.find((l) => l.name === 'Opened').args.id;

  const { result } = await chain.call(htlc, maker, 'getSwap', [id]);
  assert.equal(result[0].amount, amount - amount / 100n, 'records the received amount');

  // ...and that amount is exactly what the escrow can still pay out.
  await chain.call(htlc, taker, 'claim', [id, SECRET]);
  const takerBalance = await chain.call(token, taker, 'balanceOf', [taker.toString()]);
  const escrowLeft = await chain.call(token, taker, 'balanceOf', [htlc.address.toString()]);
  assert.equal(escrowLeft.result[0], 0n, 'no dust left behind');
  assert.ok(takerBalance.result[0] > 0n);
});

test('a token that silently fails a transfer reverts the claim', async () => {
  const ctx = await setup();
  const { chain, now, maker, taker, htlc } = ctx;
  const token = await chain.deploy('MockFalseERC20', maker);
  const amount = 1000n;
  await chain.call(token, maker, 'mint', [maker.toString(), amount]);
  await chain.call(token, maker, 'approve', [htlc.address.toString(), amount]);
  const { logs } = await chain.call(htlc, maker, 'open', [
    taker.toString(),
    token.address.toString(),
    amount,
    HASHLOCK,
    BigInt(now + 12 * HOUR),
    '0x' + '00'.repeat(32),
  ]);
  const id = logs.find((l) => l.name === 'Opened').args.id;
  await assert.rejects(chain.call(htlc, taker, 'claim', [id, SECRET]), /TransferFailed/);
});

test('swap ids are unique per maker even for identical terms', async () => {
  const ctx = await setup();
  const first = await openNative(ctx);
  const second = await openNative(ctx);
  assert.notEqual(first, second);

  // And the id a counterparty recomputes from the terms matches the real one.
  const { chain, now, maker, taker, htlc } = ctx;
  const { result } = await chain.call(htlc, taker, 'computeId', [
    maker.toString(),
    taker.toString(),
    '0x' + '00'.repeat(20),
    10n ** 18n,
    HASHLOCK,
    BigInt(now + 24 * HOUR),
    0n,
  ]);
  assert.equal(result[0], first);
});
