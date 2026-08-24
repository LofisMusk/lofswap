//! On-chain record of a swap and the byte layout it is stored in.
//!
//! The layout is hand-rolled (no borsh dependency) so the account can be
//! decoded by any client — Rust, TypeScript, Python — from a fixed offset
//! table, and so the program stays small.

use solana_program::{program_error::ProgramError, pubkey::Pubkey};

/// `LOFSWAP1` — guards against decoding a foreign account as a swap.
pub const MAGIC: [u8; 8] = *b"LOFSWAP1";
pub const STATE_LEN: usize = 8      // magic
    + 1                             // version
    + 1                             // status
    + 1                             // asset kind
    + 32                            // swap_id
    + 32                            // maker
    + 32                            // recipient
    + 32                            // mint (zero for native SOL)
    + 32                            // escrow token account (zero for native SOL)
    + 8                             // amount
    + 32                            // hashlock
    + 8                             // timelock
    + 8                             // nonce
    + 32                            // counterparty_ref
    + 32                            // secret (zero until claimed)
    + 1; // escrow bump

pub const STATE_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Open = 0,
    Claimed = 1,
    Refunded = 2,
}

impl Status {
    pub fn from_u8(value: u8) -> Result<Self, ProgramError> {
        match value {
            0 => Ok(Status::Open),
            1 => Ok(Status::Claimed),
            2 => Ok(Status::Refunded),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetKind {
    /// Native SOL, held as lamports on the swap account itself.
    Sol = 0,
    /// SPL token, held in a token account owned by the swap PDA.
    SplToken = 1,
}

impl AssetKind {
    pub fn from_u8(value: u8) -> Result<Self, ProgramError> {
        match value {
            0 => Ok(AssetKind::Sol),
            1 => Ok(AssetKind::SplToken),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapState {
    pub status: Status,
    pub asset: AssetKind,
    pub swap_id: [u8; 32],
    pub maker: Pubkey,
    pub recipient: Pubkey,
    pub mint: Pubkey,
    pub escrow_token_account: Pubkey,
    pub amount: u64,
    pub hashlock: [u8; 32],
    pub timelock: i64,
    pub nonce: u64,
    /// Swap id of the leg on the other chain (the LofSwap `swap_id`).
    pub counterparty_ref: [u8; 32],
    /// Revealed preimage; all zeroes until the swap is claimed.
    pub secret: [u8; 32],
    pub bump: u8,
}

macro_rules! take {
    ($src:expr, $cursor:expr, $len:expr) => {{
        let start = $cursor;
        $cursor += $len;
        <[u8; $len]>::try_from(&$src[start..$cursor])
            .map_err(|_| ProgramError::InvalidAccountData)?
    }};
}

impl SwapState {
    pub fn unpack(src: &[u8]) -> Result<Self, ProgramError> {
        if src.len() < STATE_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut cursor = 0usize;
        let magic = take!(src, cursor, 8);
        if magic != MAGIC {
            return Err(ProgramError::InvalidAccountData);
        }
        let version = src[cursor];
        cursor += 1;
        if version != STATE_VERSION {
            return Err(ProgramError::InvalidAccountData);
        }
        let status = Status::from_u8(src[cursor])?;
        cursor += 1;
        let asset = AssetKind::from_u8(src[cursor])?;
        cursor += 1;
        let swap_id = take!(src, cursor, 32);
        let maker = Pubkey::from(take!(src, cursor, 32));
        let recipient = Pubkey::from(take!(src, cursor, 32));
        let mint = Pubkey::from(take!(src, cursor, 32));
        let escrow_token_account = Pubkey::from(take!(src, cursor, 32));
        let amount = u64::from_le_bytes(take!(src, cursor, 8));
        let hashlock = take!(src, cursor, 32);
        let timelock = i64::from_le_bytes(take!(src, cursor, 8));
        let nonce = u64::from_le_bytes(take!(src, cursor, 8));
        let counterparty_ref = take!(src, cursor, 32);
        let secret = take!(src, cursor, 32);
        let bump = src[cursor];

        Ok(SwapState {
            status,
            asset,
            swap_id,
            maker,
            recipient,
            mint,
            escrow_token_account,
            amount,
            hashlock,
            timelock,
            nonce,
            counterparty_ref,
            secret,
            bump,
        })
    }

    pub fn pack(&self, dst: &mut [u8]) -> Result<(), ProgramError> {
        if dst.len() < STATE_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        let mut cursor = 0usize;
        let mut put = |bytes: &[u8], cursor: &mut usize| {
            dst[*cursor..*cursor + bytes.len()].copy_from_slice(bytes);
            *cursor += bytes.len();
        };
        put(&MAGIC, &mut cursor);
        put(&[STATE_VERSION], &mut cursor);
        put(&[self.status as u8], &mut cursor);
        put(&[self.asset as u8], &mut cursor);
        put(&self.swap_id, &mut cursor);
        put(self.maker.as_ref(), &mut cursor);
        put(self.recipient.as_ref(), &mut cursor);
        put(self.mint.as_ref(), &mut cursor);
        put(self.escrow_token_account.as_ref(), &mut cursor);
        put(&self.amount.to_le_bytes(), &mut cursor);
        put(&self.hashlock, &mut cursor);
        put(&self.timelock.to_le_bytes(), &mut cursor);
        put(&self.nonce.to_le_bytes(), &mut cursor);
        put(&self.counterparty_ref, &mut cursor);
        put(&self.secret, &mut cursor);
        put(&[self.bump], &mut cursor);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SwapState {
        SwapState {
            status: Status::Open,
            asset: AssetKind::SplToken,
            swap_id: [1u8; 32],
            maker: Pubkey::new_from_array([2u8; 32]),
            recipient: Pubkey::new_from_array([3u8; 32]),
            mint: Pubkey::new_from_array([4u8; 32]),
            escrow_token_account: Pubkey::new_from_array([5u8; 32]),
            amount: 25_000_000,
            hashlock: [6u8; 32],
            timelock: 1_800_000_000,
            nonce: 7,
            counterparty_ref: [8u8; 32],
            secret: [0u8; 32],
            bump: 254,
        }
    }

    #[test]
    fn pack_then_unpack_roundtrips() {
        let state = sample();
        let mut buf = vec![0u8; STATE_LEN];
        state.pack(&mut buf).unwrap();
        assert_eq!(SwapState::unpack(&buf).unwrap(), state);
    }

    #[test]
    fn foreign_accounts_are_rejected() {
        let mut buf = vec![0u8; STATE_LEN];
        assert!(
            SwapState::unpack(&buf).is_err(),
            "zeroed account is not a swap"
        );
        sample().pack(&mut buf).unwrap();
        buf[0] = b'X';
        assert!(
            SwapState::unpack(&buf).is_err(),
            "wrong magic must not decode"
        );
        sample().pack(&mut buf).unwrap();
        buf[8] = 99;
        assert!(
            SwapState::unpack(&buf).is_err(),
            "unknown version must not decode"
        );
        assert!(
            SwapState::unpack(&buf[..STATE_LEN - 1]).is_err(),
            "short account"
        );
    }
}
