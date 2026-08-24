// A whole swap against a live validator: lock, a wrong secret, a theft
// attempt, then the claim that publishes the preimage for the other leg.
//
//   solana-test-validator --reset --quiet &
//   cargo build-sbf --arch v3
//   solana program deploy target/deploy/lofswap_htlc_solana.so
//   npm install && npm run e2e -- <program id>
//
// The unit and LiteSVM suites (`cargo test-sbf`) cover the SPL leg and every
// rejection path; this script exists to prove the deployed artefact behaves the
// same way once a real validator, its loader and its clock are in the loop.
import { createHash } from "node:crypto";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

const RPC = process.env.RPC_URL ?? "http://127.0.0.1:8899";
const programArgument = process.argv[2];
if (!programArgument) {
  console.error("usage: npm run e2e -- <program id>");
  process.exit(2);
}
const PROGRAM = new PublicKey(programArgument);

/** The 32 secret bytes every leg of the reference trade is pinned to. */
const SECRET = Buffer.alloc(32, 0x9a);
const HASHLOCK = "8b9d52fd75ae21d2b827872bd084d762b24fb716dc87974668ecafcfe55df678";
const PROTOCOL = Buffer.from("lofswap-swap-v1");
const SWAP_SEED = Buffer.from("lofswap-htlc");
const STATE_LEN = 292;

const sha256 = (...parts) => createHash("sha256").update(Buffer.concat(parts)).digest();
const u64 = (value) => {
  const out = Buffer.alloc(8);
  out.writeBigInt64LE(BigInt(value));
  return out;
};

/** The same identity the program derives, recomputed from the terms alone. */
const swapId = (terms) =>
  sha256(
    PROTOCOL,
    Buffer.from("|solana|"),
    PROGRAM.toBuffer(),
    terms.maker.toBuffer(),
    terms.recipient.toBuffer(),
    terms.mint.toBuffer(),
    u64(terms.amount),
    terms.hashlock,
    u64(terms.timelock),
    u64(terms.nonce),
  );

const lockPayload = (terms) =>
  Buffer.concat([
    Buffer.from([0, 0]), // Lock, native SOL
    terms.recipient.toBuffer(),
    u64(terms.amount),
    terms.hashlock,
    u64(terms.timelock),
    u64(terms.nonce),
    Buffer.alloc(32), // counterparty_ref
  ]);

let failures = 0;
const check = (ok, what) => {
  console.log(`${ok ? "  ok  " : " FAIL "} ${what}`);
  if (!ok) failures += 1;
};

const connection = new Connection(RPC, "confirmed");
const send = (instruction, signers) =>
  sendAndConfirmTransaction(connection, new Transaction().add(instruction), signers, {
    commitment: "confirmed",
    skipPreflight: true,
  });
const rejects = async (instruction, signers) => {
  try {
    await send(instruction, signers);
    return false;
  } catch {
    return true;
  }
};
const funded = async (lamports) => {
  const keypair = Keypair.generate();
  const signature = await connection.requestAirdrop(keypair.publicKey, lamports);
  await connection.confirmTransaction(signature, "confirmed");
  return keypair;
};

const deployed = await connection.getAccountInfo(PROGRAM);
check(deployed?.executable === true, `${PROGRAM.toBase58()} is deployed and executable`);
if (!deployed?.executable) process.exit(1);

const maker = await funded(10 * LAMPORTS_PER_SOL);
const recipient = await funded(LAMPORTS_PER_SOL);
const relayer = await funded(LAMPORTS_PER_SOL);

const terms = {
  maker: maker.publicKey,
  recipient: recipient.publicKey,
  mint: SystemProgram.programId, // the all-zero key: no mint, native SOL
  amount: 2 * LAMPORTS_PER_SOL,
  hashlock: sha256(SECRET),
  timelock: Math.floor(Date.now() / 1000) + 12 * 60 * 60,
  nonce: 1,
};
check(terms.hashlock.toString("hex") === HASHLOCK, "the hashlock is the one every leg is pinned to");

const id = swapId(terms);
const [escrow] = PublicKey.findProgramAddressSync([SWAP_SEED, id], PROGRAM);

await send(
  new TransactionInstruction({
    programId: PROGRAM,
    keys: [
      { pubkey: maker.publicKey, isSigner: true, isWritable: true },
      { pubkey: escrow, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: lockPayload(terms),
  }),
  [maker],
);

const rent = await connection.getMinimumBalanceForRentExemption(STATE_LEN);
const locked = await connection.getAccountInfo(escrow);
check(locked !== null, `lock mined, escrow ${escrow.toBase58()} opened`);
check(locked.data.subarray(0, 8).toString() === "LOFSWAP1", "the escrow decodes as a LofSwap swap");
check(locked.data[9] === 0, "the swap is open");
check(locked.data.subarray(11, 43).equals(id), "the account records the swap id");
check(locked.data.subarray(259, 291).equals(Buffer.alloc(32)), "no secret on chain yet");
check(locked.lamports === rent + terms.amount, "the escrow holds the locked amount plus its rent");

const claim = (payer, beneficiary, secret) =>
  new TransactionInstruction({
    programId: PROGRAM,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: escrow, isSigner: false, isWritable: true },
      { pubkey: beneficiary, isSigner: false, isWritable: true },
    ],
    data: Buffer.concat([Buffer.from([1]), secret]),
  });

check(
  await rejects(claim(relayer, recipient.publicKey, Buffer.alloc(32, 0x9b)), [relayer]),
  "a wrong secret claims nothing",
);
check(
  await rejects(claim(relayer, relayer.publicKey, SECRET), [relayer]),
  "the secret alone cannot redirect the payout",
);

const before = await connection.getBalance(recipient.publicKey);
const signature = await send(claim(relayer, recipient.publicKey, SECRET), [relayer]);
check(
  (await connection.getBalance(recipient.publicKey)) - before === terms.amount,
  "the recipient is paid in full by somebody else's transaction",
);

const settled = await connection.getAccountInfo(escrow);
check(settled.data[9] === 1, "the swap is marked claimed");
check(settled.data.subarray(259, 291).equals(SECRET), "the preimage is readable on chain");
check(settled.lamports === rent, "only the rent stays behind");

const transaction = await connection.getTransaction(signature, { commitment: "confirmed" });
check(
  transaction.meta.logMessages.some((line) => line.includes(SECRET.toString("hex"))),
  "the claim publishes the secret the other leg needs",
);

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed against a live validator");
process.exit(failures ? 1 : 0);
