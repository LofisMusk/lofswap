//! Program logic: lock, claim, refund, close.
//!
//! The escrow is a PDA derived from the swap id, so nobody holds a key for it
//! and only these four paths can move its funds. Native SOL sits in the swap
//! account's own lamports; SPL tokens sit in a token account owned by the PDA.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_sdk_ids::system_program;
use solana_system_interface::instruction as system_instruction;

use crate::{
    instruction::HtlcInstruction,
    state::{AssetKind, Status, SwapState, STATE_LEN},
    swap_id::{hashlock_for, swap_address, swap_id, SWAP_SEED},
};

/// Mirrors the LofSwap chain's own bounds so both legs speak about comparable
/// deadlines. The floor is lower than LofSwap's 30 minutes on purpose: the leg
/// that settles second must be able to use a clearly shorter timelock.
pub const MIN_LOCK_SECONDS: i64 = 10 * 60;
pub const MAX_LOCK_SECONDS: i64 = 30 * 24 * 60 * 60;

/// SPL token account layout: mint at 0..32, owner at 32..64, amount at 64..72.
const TOKEN_ACCOUNT_LEN: usize = 165;
/// `TransferChecked` instruction tag of the SPL token program.
const TOKEN_IX_TRANSFER_CHECKED: u8 = 12;
/// `CloseAccount` instruction tag of the SPL token program.
const TOKEN_IX_CLOSE_ACCOUNT: u8 = 9;

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    match HtlcInstruction::unpack(data)? {
        HtlcInstruction::Lock {
            asset,
            recipient,
            amount,
            hashlock,
            timelock,
            nonce,
            counterparty_ref,
        } => lock(
            program_id,
            accounts,
            asset,
            recipient,
            amount,
            hashlock,
            timelock,
            nonce,
            counterparty_ref,
        ),
        HtlcInstruction::Claim { secret } => settle(program_id, accounts, Some(secret)),
        HtlcInstruction::Refund => settle(program_id, accounts, None),
        HtlcInstruction::Close => close(program_id, accounts),
    }
}

#[allow(clippy::too_many_arguments)]
fn lock(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    asset: AssetKind,
    recipient: Pubkey,
    amount: u64,
    hashlock: [u8; 32],
    timelock: i64,
    nonce: u64,
    counterparty_ref: [u8; 32],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let maker = next_account_info(iter)?;
    let swap = next_account_info(iter)?;
    let system = next_account_info(iter)?;

    if !maker.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !system_program::check_id(system.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if amount == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    if recipient == *maker.key || recipient == Pubkey::default() {
        msg!("recipient must be somebody else");
        return Err(ProgramError::InvalidArgument);
    }

    let now = Clock::get()?.unix_timestamp;
    let lifetime = timelock.saturating_sub(now);
    if !(MIN_LOCK_SECONDS..=MAX_LOCK_SECONDS).contains(&lifetime) {
        msg!(
            "timelock must be {}..{}s away",
            MIN_LOCK_SECONDS,
            MAX_LOCK_SECONDS
        );
        return Err(ProgramError::InvalidArgument);
    }

    // SPL swaps additionally name the mint and the two token accounts.
    let (mint_key, escrow_token_key, spl) = match asset {
        AssetKind::Sol => (Pubkey::default(), Pubkey::default(), None),
        AssetKind::SplToken => {
            let mint = next_account_info(iter)?;
            let maker_token = next_account_info(iter)?;
            let escrow_token = next_account_info(iter)?;
            let token_program = next_account_info(iter)?;
            (
                *mint.key,
                *escrow_token.key,
                Some((mint, maker_token, escrow_token, token_program)),
            )
        }
    };

    let id = swap_id(
        program_id, maker.key, &recipient, &mint_key, amount, &hashlock, timelock, nonce,
    );
    let (expected_swap, bump) = swap_address(program_id, &id);
    if expected_swap != *swap.key {
        msg!("swap account does not match the swap terms");
        return Err(ProgramError::InvalidSeeds);
    }
    if !swap.data_is_empty() || swap.owner != &system_program::id() {
        msg!("this swap already exists");
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    // Create the escrow account. Transfer/allocate/assign rather than
    // `create_account`, so a PDA somebody pre-funded with lamports can still
    // be initialised instead of being bricked forever.
    let rent = Rent::get()?.minimum_balance(STATE_LEN);
    let needed = match asset {
        AssetKind::Sol => rent
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?,
        AssetKind::SplToken => rent,
    };
    let seeds: &[&[u8]] = &[SWAP_SEED, &id, &[bump]];
    let missing = needed.saturating_sub(swap.lamports());
    if missing > 0 {
        invoke(
            &system_instruction::transfer(maker.key, swap.key, missing),
            &[maker.clone(), swap.clone(), system.clone()],
        )?;
    }
    invoke_signed(
        &system_instruction::allocate(swap.key, STATE_LEN as u64),
        &[swap.clone(), system.clone()],
        &[seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(swap.key, program_id),
        &[swap.clone(), system.clone()],
        &[seeds],
    )?;

    if let Some((mint, maker_token, escrow_token, token_program)) = spl {
        check_token_account(escrow_token, token_program.key, mint.key, &expected_swap)?;
        check_token_account_program(maker_token, token_program.key)?;
        // The maker signs this transfer themselves; the escrow account is the
        // PDA, so from here on only this program can move the tokens.
        invoke(
            &transfer_checked_ix(
                token_program.key,
                maker_token.key,
                mint.key,
                escrow_token.key,
                maker.key,
                amount,
                mint_decimals(mint)?,
            ),
            &[
                maker_token.clone(),
                mint.clone(),
                escrow_token.clone(),
                maker.clone(),
                token_program.clone(),
            ],
        )?;
    }

    let state = SwapState {
        status: Status::Open,
        asset,
        swap_id: id,
        maker: *maker.key,
        recipient,
        mint: mint_key,
        escrow_token_account: escrow_token_key,
        amount,
        hashlock,
        timelock,
        nonce,
        counterparty_ref,
        secret: [0u8; 32],
        bump,
    };
    state.pack(&mut swap.try_borrow_mut_data()?)?;
    msg!("lofswap: locked swap {}", bs58_id(&id));
    Ok(())
}

/// Claim (with a secret) and refund (without) differ only in who gets paid and
/// which side of the timelock they are allowed on.
fn settle(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    secret: Option<[u8; 32]>,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let payer = next_account_info(iter)?;
    let swap = next_account_info(iter)?;
    let beneficiary = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if swap.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    let mut state = SwapState::unpack(&swap.try_borrow_data()?)?;
    if state.status != Status::Open {
        msg!("swap is already settled");
        return Err(ProgramError::InvalidAccountData);
    }
    let (expected_swap, bump) = swap_address(program_id, &state.swap_id);
    if expected_swap != *swap.key || bump != state.bump {
        return Err(ProgramError::InvalidSeeds);
    }

    let now = Clock::get()?.unix_timestamp;
    match secret {
        Some(secret) => {
            if now >= state.timelock {
                msg!("claim window closed");
                return Err(ProgramError::InvalidArgument);
            }
            if hashlock_for(&secret) != state.hashlock {
                msg!("secret does not match the hashlock");
                return Err(ProgramError::InvalidArgument);
            }
            if *beneficiary.key != state.recipient {
                msg!("a claim must pay the recipient");
                return Err(ProgramError::InvalidArgument);
            }
            state.status = Status::Claimed;
            state.secret = secret;
        }
        None => {
            if now < state.timelock {
                msg!("swap has not expired yet");
                return Err(ProgramError::InvalidArgument);
            }
            if *beneficiary.key != state.maker {
                msg!("a refund must pay the maker");
                return Err(ProgramError::InvalidArgument);
            }
            state.status = Status::Refunded;
        }
    }

    match state.asset {
        AssetKind::Sol => {
            // The PDA is owned by this program, so its lamports may be moved
            // directly. The rent-exempt remainder stays behind and is returned
            // by `Close`.
            let mut swap_lamports = swap.try_borrow_mut_lamports()?;
            let mut beneficiary_lamports = beneficiary.try_borrow_mut_lamports()?;
            **swap_lamports = swap_lamports
                .checked_sub(state.amount)
                .ok_or(ProgramError::InsufficientFunds)?;
            **beneficiary_lamports = beneficiary_lamports
                .checked_add(state.amount)
                .ok_or(ProgramError::ArithmeticOverflow)?;
        }
        AssetKind::SplToken => {
            let escrow_token = next_account_info(iter)?;
            let beneficiary_token = next_account_info(iter)?;
            let mint = next_account_info(iter)?;
            let token_program = next_account_info(iter)?;

            if *escrow_token.key != state.escrow_token_account {
                return Err(ProgramError::InvalidArgument);
            }
            if *mint.key != state.mint {
                return Err(ProgramError::InvalidArgument);
            }
            check_token_account(escrow_token, token_program.key, mint.key, &expected_swap)?;
            check_token_account(
                beneficiary_token,
                token_program.key,
                mint.key,
                beneficiary.key,
            )?;

            let seeds: &[&[u8]] = &[SWAP_SEED, &state.swap_id, &[state.bump]];
            invoke_signed(
                &transfer_checked_ix(
                    token_program.key,
                    escrow_token.key,
                    mint.key,
                    beneficiary_token.key,
                    swap.key,
                    state.amount,
                    mint_decimals(mint)?,
                ),
                &[
                    escrow_token.clone(),
                    mint.clone(),
                    beneficiary_token.clone(),
                    swap.clone(),
                    token_program.clone(),
                ],
                &[seeds],
            )?;
        }
    }

    state.pack(&mut swap.try_borrow_mut_data()?)?;
    if let Some(secret) = secret {
        // Logged so the counterparty can lift the preimage straight out of the
        // transaction and settle the other leg.
        msg!(
            "lofswap: claimed {} secret {}",
            bs58_id(&state.swap_id),
            hex32(&secret)
        );
    } else {
        msg!("lofswap: refunded {}", bs58_id(&state.swap_id));
    }
    Ok(())
}

/// Returns the rent of a settled swap to its maker.
///
/// Gated on the timelock so the revealed secret stays readable on chain at
/// least until the deadline both parties agreed on.
fn close(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let maker = next_account_info(iter)?;
    let swap = next_account_info(iter)?;

    if !maker.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if swap.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    let state = SwapState::unpack(&swap.try_borrow_data()?)?;
    if state.status == Status::Open {
        msg!("swap is still open");
        return Err(ProgramError::InvalidAccountData);
    }
    if *maker.key != state.maker {
        return Err(ProgramError::InvalidArgument);
    }
    if Clock::get()?.unix_timestamp < state.timelock {
        msg!("wait for the timelock so the secret stays readable");
        return Err(ProgramError::InvalidArgument);
    }

    if state.asset == AssetKind::SplToken {
        let escrow_token = next_account_info(iter)?;
        let token_program = next_account_info(iter)?;
        if *escrow_token.key != state.escrow_token_account {
            return Err(ProgramError::InvalidArgument);
        }
        check_token_account_program(escrow_token, token_program.key)?;
        let seeds: &[&[u8]] = &[SWAP_SEED, &state.swap_id, &[state.bump]];
        invoke_signed(
            &close_account_ix(token_program.key, escrow_token.key, maker.key, swap.key),
            &[
                escrow_token.clone(),
                maker.clone(),
                swap.clone(),
                token_program.clone(),
            ],
            &[seeds],
        )?;
    }

    let mut swap_lamports = swap.try_borrow_mut_lamports()?;
    let mut maker_lamports = maker.try_borrow_mut_lamports()?;
    **maker_lamports = maker_lamports
        .checked_add(**swap_lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    **swap_lamports = 0;
    drop(swap_lamports);
    drop(maker_lamports);

    let mut data = swap.try_borrow_mut_data()?;
    data.fill(0);
    Ok(())
}

/// Rejects anything that is not a token account of `mint` owned by `owner`.
fn check_token_account(
    account: &AccountInfo,
    token_program: &Pubkey,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Result<(), ProgramError> {
    check_token_account_program(account, token_program)?;
    let data = account.try_borrow_data()?;
    if data.len() < TOKEN_ACCOUNT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    if &data[0..32] != mint.as_ref() {
        msg!("token account holds the wrong mint");
        return Err(ProgramError::InvalidArgument);
    }
    if &data[32..64] != owner.as_ref() {
        msg!("token account has the wrong owner");
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

fn check_token_account_program(
    account: &AccountInfo,
    token_program: &Pubkey,
) -> Result<(), ProgramError> {
    if account.owner != token_program {
        msg!("token account is not owned by the token program");
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

fn mint_decimals(mint: &AccountInfo) -> Result<u8, ProgramError> {
    // Mint layout: supply at 36..44, decimals at 44.
    let data = mint.try_borrow_data()?;
    data.get(44)
        .copied()
        .ok_or(ProgramError::InvalidAccountData)
}

fn transfer_checked_ix(
    token_program: &Pubkey,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
) -> solana_program::instruction::Instruction {
    use solana_program::instruction::{AccountMeta, Instruction};
    let mut data = Vec::with_capacity(10);
    data.push(TOKEN_IX_TRANSFER_CHECKED);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

fn close_account_ix(
    token_program: &Pubkey,
    account: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
) -> solana_program::instruction::Instruction {
    use solana_program::instruction::{AccountMeta, Instruction};
    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data: vec![TOKEN_IX_CLOSE_ACCOUNT],
    }
}

fn bs58_id(id: &[u8; 32]) -> String {
    solana_program::pubkey::Pubkey::from(*id).to_string()
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::STATE_VERSION;

    #[test]
    fn timelock_window_matches_the_documented_bounds() {
        assert_eq!(MIN_LOCK_SECONDS, 600);
        assert_eq!(MAX_LOCK_SECONDS, 2_592_000);
        // The second leg of a trade must be able to expire well before a
        // 24h LofSwap leg, whose own floor is 30 minutes.
        const { assert!(MIN_LOCK_SECONDS < 30 * 60) };
    }

    #[test]
    fn transfer_checked_payload_matches_the_spl_layout() {
        let program = Pubkey::new_from_array([1u8; 32]);
        let ix = transfer_checked_ix(
            &program,
            &Pubkey::new_from_array([2u8; 32]),
            &Pubkey::new_from_array([3u8; 32]),
            &Pubkey::new_from_array([4u8; 32]),
            &Pubkey::new_from_array([5u8; 32]),
            25_000_000,
            6,
        );
        assert_eq!(ix.data[0], TOKEN_IX_TRANSFER_CHECKED);
        assert_eq!(
            u64::from_le_bytes(ix.data[1..9].try_into().unwrap()),
            25_000_000
        );
        assert_eq!(ix.data[9], 6);
        assert_eq!(ix.accounts.len(), 4);
        assert!(ix.accounts[3].is_signer, "the authority signs the transfer");
    }

    #[test]
    fn state_length_is_what_the_layout_adds_up_to() {
        // magic + version + status + asset + eight 32-byte fields
        // (swap id, maker, recipient, mint, escrow, hashlock, ref, secret)
        // + amount + timelock + nonce + bump
        assert_eq!(STATE_LEN, 8 + 1 + 1 + 1 + 32 * 8 + 8 * 3 + 1);
        assert_eq!(STATE_LEN, 292);
        assert_eq!(STATE_VERSION, 1);
    }

    #[test]
    fn hex_helper_is_lowercase_and_padded() {
        assert_eq!(hex32(&[0x0au8; 32]), "0a".repeat(32));
    }
}
