//! Test harness: the compiled SBF program running in the Solana runtime.
//!
//! Every test here loads `target/deploy/lofswap_htlc_solana.so` — the exact
//! artefact `cargo build-sbf` produces and `solana program deploy` uploads —
//! into LiteSVM, the agave SVM with the SPL token program preloaded. Failures
//! are therefore real runtime failures, not host-side simulations.
//!
//! Run with `cargo test-sbf`, which builds the artefact first and points
//! `SBF_OUT_DIR` at it.

#![allow(dead_code)]

use std::path::PathBuf;

use litesvm::{types::TransactionResult, LiteSVM};
use lofswap_htlc_solana::{
    instruction::HtlcInstruction,
    state::{AssetKind, SwapState},
    swap_id::{swap_address, swap_id},
};
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program::pubkey::Pubkey;
use solana_program_option::COption;
use solana_program_pack::Pack;
use solana_signer::Signer;
use solana_transaction::Transaction;
use spl_token_interface::state::{Account as TokenAccount, AccountState, Mint};

/// Re-exported so `use common::*;` brings `keypair.pubkey()` with it.
pub use solana_signer::Signer as _Signer;

/// The 32 secret bytes every leg of the reference trade is pinned to, and the
/// SHA-256 digest the LofSwap chain and `LofSwapHTLC.sol` compute from them.
pub const SECRET: [u8; 32] = [0x9a; 32];
pub const HASHLOCK_HEX: &str = "8b9d52fd75ae21d2b827872bd084d762b24fb716dc87974668ecafcfe55df678";

/// Wall clock the tests start at, and a few useful offsets.
pub const NOW: i64 = 1_780_000_000;
pub const HOUR: i64 = 60 * 60;
pub const DAY: i64 = 24 * HOUR;

pub const SYSTEM_PROGRAM: Address = Address::new_from_array([0u8; 32]);
pub const TOKEN_PROGRAM: Address =
    Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

pub const SOL: u64 = 1_000_000_000;
/// LiteSVM charges the mainnet 5000 lamports per signature.
pub const FEE: u64 = 5_000;

/// Where `cargo build-sbf` / `cargo test-sbf` leaves the on-chain artefact.
fn program_binary() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBF_OUT_DIR").or_else(|| std::env::var_os("BPF_OUT_DIR")) {
        return PathBuf::from(dir).join("lofswap_htlc_solana.so");
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/deploy/lofswap_htlc_solana.so")
}

pub struct Env {
    pub svm: LiteSVM,
    pub program: Address,
}

impl Env {
    pub fn new() -> Self {
        let binary = program_binary();
        let bytes = std::fs::read(&binary).unwrap_or_else(|err| {
            panic!(
                "{}: {err}\nBuild the program first: `cargo build-sbf`, or run the suite with \
                 `cargo test-sbf`.",
                binary.display()
            )
        });
        let program = Address::new_from_array([
            0x10, 0xf5, 0x3a, 0x20, 0x88, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11,
        ]);
        let mut svm = LiteSVM::new();
        svm.add_program(program, &bytes)
            .expect("the SBF artefact must load into the runtime");
        let mut env = Env { svm, program };
        env.set_time(NOW);
        env
    }

    pub fn set_time(&mut self, unix_timestamp: i64) {
        let mut clock: Clock = self.svm.get_sysvar();
        clock.unix_timestamp = unix_timestamp;
        self.svm.set_sysvar(&clock);
    }

    pub fn advance(&mut self, seconds: i64) {
        let clock: Clock = self.svm.get_sysvar();
        self.set_time(clock.unix_timestamp + seconds);
    }

    pub fn funded(&mut self, lamports: u64) -> Keypair {
        let kp = Keypair::new();
        self.svm.airdrop(&kp.pubkey(), lamports).unwrap();
        kp
    }

    pub fn send(&mut self, ix: Instruction, signers: &[&Keypair]) -> TransactionResult {
        let payer = signers[0].pubkey();
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer),
            signers,
            self.svm.latest_blockhash(),
        );
        let result = self.svm.send_transaction(tx);
        // Keep every transaction in a suite distinct, whatever it contained.
        self.svm.expire_blockhash();
        result
    }

    pub fn balance(&self, address: &Address) -> u64 {
        self.svm.get_balance(address).unwrap_or_default()
    }

    pub fn account_data(&self, address: &Address) -> Option<Vec<u8>> {
        self.svm.get_account(address).map(|account| account.data)
    }

    pub fn state(&self, swap: &Address) -> SwapState {
        let data = self
            .account_data(swap)
            .expect("the swap account should exist");
        SwapState::unpack(&data).expect("the swap account should decode")
    }

    pub fn state_rent(&self) -> u64 {
        self.svm
            .minimum_balance_for_rent_exemption(lofswap_htlc_solana::state::STATE_LEN)
    }

    pub fn token_rent(&self) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(TokenAccount::LEN)
    }

    /// Writes an initialised SPL mint straight into the ledger.
    pub fn mint(&mut self, decimals: u8) -> Address {
        let address = Keypair::new().pubkey();
        let mut data = vec![0u8; Mint::LEN];
        Mint {
            mint_authority: COption::None,
            supply: u64::MAX / 2,
            decimals,
            is_initialized: true,
            freeze_authority: COption::None,
        }
        .pack_into_slice(&mut data);
        self.put(address, data, TOKEN_PROGRAM, Mint::LEN);
        address
    }

    /// Writes an initialised SPL token account holding `amount` of `mint`.
    pub fn token_account(&mut self, mint: Address, owner: Address, amount: u64) -> Address {
        let address = Keypair::new().pubkey();
        self.token_account_at(address, mint, owner, amount);
        address
    }

    pub fn token_account_at(&mut self, address: Address, mint: Address, owner: Address, amount: u64) {
        let mut data = vec![0u8; TokenAccount::LEN];
        TokenAccount {
            mint,
            owner,
            amount,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        }
        .pack_into_slice(&mut data);
        self.put(address, data, TOKEN_PROGRAM, TokenAccount::LEN);
    }

    fn put(&mut self, address: Address, data: Vec<u8>, owner: Address, len: usize) {
        let lamports = self.svm.minimum_balance_for_rent_exemption(len);
        self.svm
            .set_account(
                address,
                Account {
                    lamports,
                    data,
                    owner,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    }

    pub fn token_balance(&self, account: &Address) -> u64 {
        let data = self
            .account_data(account)
            .expect("the token account should exist");
        TokenAccount::unpack(&data)
            .expect("the token account should decode")
            .amount
    }
}

/// The terms a swap id commits to. Both parties can recompute the escrow
/// address from these alone, which is what makes the escrow auditable.
#[derive(Clone)]
pub struct Terms {
    pub asset: AssetKind,
    pub maker: Address,
    pub recipient: Address,
    pub mint: Address,
    pub amount: u64,
    pub hashlock: [u8; 32],
    pub timelock: i64,
    pub nonce: u64,
    pub counterparty_ref: [u8; 32],
}

impl Terms {
    pub fn sol(maker: Address, recipient: Address, amount: u64) -> Self {
        Terms {
            asset: AssetKind::Sol,
            maker,
            recipient,
            mint: SYSTEM_PROGRAM, // the all-zero key: "no mint"
            amount,
            hashlock: lofswap_htlc_solana::swap_id::hashlock_for(&SECRET),
            timelock: NOW + 12 * HOUR,
            nonce: 0,
            counterparty_ref: [0u8; 32],
        }
    }

    pub fn spl(maker: Address, recipient: Address, mint: Address, amount: u64) -> Self {
        Terms {
            asset: AssetKind::SplToken,
            mint,
            ..Terms::sol(maker, recipient, amount)
        }
    }

    pub fn id(&self, program: &Address) -> [u8; 32] {
        swap_id(
            &pk(program),
            &pk(&self.maker),
            &pk(&self.recipient),
            &pk(&self.mint),
            self.amount,
            &self.hashlock,
            self.timelock,
            self.nonce,
        )
    }

    pub fn escrow(&self, program: &Address) -> Address {
        let (address, _bump) = swap_address(&pk(program), &self.id(program));
        addr(&address)
    }

    fn payload(&self) -> Vec<u8> {
        HtlcInstruction::Lock {
            asset: self.asset,
            recipient: pk(&self.recipient),
            amount: self.amount,
            hashlock: self.hashlock,
            timelock: self.timelock,
            nonce: self.nonce,
            counterparty_ref: self.counterparty_ref,
        }
        .pack()
    }

    /// `Lock` for a native SOL escrow.
    pub fn lock_sol(&self, program: &Address) -> Instruction {
        self.lock_sol_into(program, self.escrow(program))
    }

    /// `Lock` naming an escrow account of the caller's choosing — used to prove
    /// the program insists on the address derived from the terms.
    pub fn lock_sol_into(&self, program: &Address, swap: Address) -> Instruction {
        Instruction {
            program_id: *program,
            accounts: vec![
                AccountMeta::new(self.maker, true),
                AccountMeta::new(swap, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data: self.payload(),
        }
    }

    /// `Lock` for an SPL escrow.
    pub fn lock_spl(
        &self,
        program: &Address,
        maker_token: Address,
        escrow_token: Address,
    ) -> Instruction {
        Instruction {
            program_id: *program,
            accounts: vec![
                AccountMeta::new(self.maker, true),
                AccountMeta::new(self.escrow(program), false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(maker_token, false),
                AccountMeta::new(escrow_token, false),
                AccountMeta::new_readonly(TOKEN_PROGRAM, false),
            ],
            data: self.payload(),
        }
    }
}

/// `Claim` / `Refund` against a native SOL escrow.
pub fn settle_sol(
    program: &Address,
    swap: Address,
    payer: Address,
    beneficiary: Address,
    secret: Option<[u8; 32]>,
) -> Instruction {
    Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(swap, false),
            AccountMeta::new(beneficiary, false),
        ],
        data: settle_payload(secret),
    }
}

/// `Claim` / `Refund` against an SPL escrow.
#[allow(clippy::too_many_arguments)]
pub fn settle_spl(
    program: &Address,
    swap: Address,
    payer: Address,
    beneficiary: Address,
    escrow_token: Address,
    beneficiary_token: Address,
    mint: Address,
    secret: Option<[u8; 32]>,
) -> Instruction {
    Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(swap, false),
            AccountMeta::new_readonly(beneficiary, false),
            AccountMeta::new(escrow_token, false),
            AccountMeta::new(beneficiary_token, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM, false),
        ],
        data: settle_payload(secret),
    }
}

fn settle_payload(secret: Option<[u8; 32]>) -> Vec<u8> {
    match secret {
        Some(secret) => HtlcInstruction::Claim { secret }.pack(),
        None => HtlcInstruction::Refund.pack(),
    }
}

pub fn close(program: &Address, swap: Address, maker: Address) -> Instruction {
    Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new(maker, true),
            AccountMeta::new(swap, false),
        ],
        data: HtlcInstruction::Close.pack(),
    }
}

pub fn close_spl(
    program: &Address,
    swap: Address,
    maker: Address,
    escrow_token: Address,
) -> Instruction {
    Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new(maker, true),
            AccountMeta::new(swap, false),
            AccountMeta::new(escrow_token, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM, false),
        ],
        data: HtlcInstruction::Close.pack(),
    }
}

/// Asserts the transaction was rejected, and that the runtime error or the
/// program's own log says why.
pub fn rejected(result: TransactionResult, because: &str) {
    let failure = match result {
        Ok(meta) => panic!(
            "expected a rejection mentioning {because:?}, but the transaction succeeded:\n{}",
            meta.pretty_logs()
        ),
        Err(failure) => failure,
    };
    let error = format!("{:?}", failure.err);
    let mentioned = error.contains(because)
        || failure
            .meta
            .logs
            .iter()
            .any(|line| line.contains(because));
    assert!(
        mentioned,
        "expected a rejection mentioning {because:?}, got {error}:\n{}",
        failure.meta.pretty_logs()
    );
}

pub fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn unhex32(value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// The runtime and the program crate carry their own `Pubkey` types; both are
/// the same 32 bytes.
pub fn pk(address: &Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

pub fn addr(pubkey: &Pubkey) -> Address {
    Address::new_from_array(pubkey.to_bytes())
}
