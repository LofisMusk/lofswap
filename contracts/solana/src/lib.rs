//! LofSwap HTLC — the Solana leg of a cross-chain atomic swap.
//!
//! This program is the Solana counterpart of the `SwapLock` / `SwapClaim` /
//! `SwapRefund` transactions on the LofSwap chain and of `LofSwapHTLC.sol` on
//! EVM chains. All three hash the same 32-byte secret with SHA-256, so one
//! preimage unlocks every leg of a trade:
//!
//! ```text
//! LofSwap        sha256(secret)          (blockchain-core::swap)
//! EVM            sha256(abi.encodePacked(secret))
//! Solana         sha256(secret)          (this program)
//! ```
//!
//! Funds live at a program-derived address that nobody holds a key for, and
//! can only move by revealing the preimage before the timelock (claim) or by
//! waiting it out (refund).

pub mod instruction;
pub mod processor;
pub mod state;
pub mod swap_id;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use solana_program::{
        account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, pubkey::Pubkey,
    };

    entrypoint!(process_instruction);

    fn process_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        crate::processor::process(program_id, accounts, instruction_data)
    }
}
