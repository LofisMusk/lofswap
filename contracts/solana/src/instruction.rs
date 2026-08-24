//! Instruction encoding for the LofSwap HTLC program.
//!
//! Hand-rolled little-endian encoding: one tag byte followed by fixed-width
//! fields, so any client language can build the payload without a schema
//! library.

use solana_program::{program_error::ProgramError, pubkey::Pubkey};

use crate::state::AssetKind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HtlcInstruction {
    /// Locks SOL or SPL tokens under a hashlock.
    ///
    /// Accounts (SOL):
    ///   0. `[signer, writable]` maker
    ///   1. `[writable]`         swap PDA
    ///   2. `[]`                 system program
    ///
    /// Accounts (SPL token) additionally:
    ///   3. `[]`                 mint
    ///   4. `[writable]`         maker token account
    ///   5. `[writable]`         escrow token account, owned by the swap PDA
    ///   6. `[]`                 SPL token program
    Lock {
        asset: AssetKind,
        recipient: Pubkey,
        amount: u64,
        hashlock: [u8; 32],
        timelock: i64,
        nonce: u64,
        counterparty_ref: [u8; 32],
    },
    /// Reveals the preimage and pays the recipient.
    ///
    /// Accounts (SOL):
    ///   0. `[signer]`   payer of the transaction (anyone)
    ///   1. `[writable]` swap PDA
    ///   2. `[writable]` recipient
    ///
    /// Accounts (SPL token) additionally:
    ///   3. `[writable]` escrow token account
    ///   4. `[writable]` recipient token account
    ///   5. `[]`         mint
    ///   6. `[]`         SPL token program
    Claim { secret: [u8; 32] },
    /// Returns an expired escrow to its maker. Same accounts as `Claim`, with
    /// the maker in place of the recipient.
    Refund,
    /// Reclaims the rent of a settled swap once its timelock has passed.
    ///
    /// Accounts (SOL):
    ///   0. `[signer]`   maker
    ///   1. `[writable]` swap PDA
    ///
    /// Accounts (SPL token) additionally:
    ///   2. `[writable]` escrow token account
    ///   3. `[]`         SPL token program
    Close,
}

impl HtlcInstruction {
    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        let (tag, rest) = input
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        match tag {
            0 => {
                if rest.len() < 1 + 32 + 8 + 32 + 8 + 8 + 32 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let asset = AssetKind::from_u8(rest[0])?;
                let mut cursor = 1usize;
                let recipient = Pubkey::from(read_array::<32>(rest, &mut cursor)?);
                let amount = u64::from_le_bytes(read_array::<8>(rest, &mut cursor)?);
                let hashlock = read_array::<32>(rest, &mut cursor)?;
                let timelock = i64::from_le_bytes(read_array::<8>(rest, &mut cursor)?);
                let nonce = u64::from_le_bytes(read_array::<8>(rest, &mut cursor)?);
                let counterparty_ref = read_array::<32>(rest, &mut cursor)?;
                Ok(HtlcInstruction::Lock {
                    asset,
                    recipient,
                    amount,
                    hashlock,
                    timelock,
                    nonce,
                    counterparty_ref,
                })
            }
            1 => {
                let mut cursor = 0usize;
                Ok(HtlcInstruction::Claim {
                    secret: read_array::<32>(rest, &mut cursor)?,
                })
            }
            2 => Ok(HtlcInstruction::Refund),
            3 => Ok(HtlcInstruction::Close),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }

    pub fn pack(&self) -> Vec<u8> {
        match self {
            HtlcInstruction::Lock {
                asset,
                recipient,
                amount,
                hashlock,
                timelock,
                nonce,
                counterparty_ref,
            } => {
                let mut out = Vec::with_capacity(1 + 1 + 32 + 8 + 32 + 8 + 8 + 32);
                out.push(0);
                out.push(*asset as u8);
                out.extend_from_slice(recipient.as_ref());
                out.extend_from_slice(&amount.to_le_bytes());
                out.extend_from_slice(hashlock);
                out.extend_from_slice(&timelock.to_le_bytes());
                out.extend_from_slice(&nonce.to_le_bytes());
                out.extend_from_slice(counterparty_ref);
                out
            }
            HtlcInstruction::Claim { secret } => {
                let mut out = Vec::with_capacity(33);
                out.push(1);
                out.extend_from_slice(secret);
                out
            }
            HtlcInstruction::Refund => vec![2],
            HtlcInstruction::Close => vec![3],
        }
    }
}

fn read_array<const N: usize>(src: &[u8], cursor: &mut usize) -> Result<[u8; N], ProgramError> {
    let end = cursor
        .checked_add(N)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let slice = src
        .get(*cursor..end)
        .ok_or(ProgramError::InvalidInstructionData)?;
    *cursor = end;
    <[u8; N]>::try_from(slice).map_err(|_| ProgramError::InvalidInstructionData)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instructions_roundtrip() {
        let lock = HtlcInstruction::Lock {
            asset: AssetKind::SplToken,
            recipient: Pubkey::new_from_array([3u8; 32]),
            amount: 25_000_000,
            hashlock: [4u8; 32],
            timelock: 1_800_000_000,
            nonce: 9,
            counterparty_ref: [5u8; 32],
        };
        for ix in [
            lock,
            HtlcInstruction::Claim { secret: [7u8; 32] },
            HtlcInstruction::Refund,
            HtlcInstruction::Close,
        ] {
            assert_eq!(HtlcInstruction::unpack(&ix.pack()).unwrap(), ix);
        }
    }

    #[test]
    fn truncated_or_unknown_payloads_are_rejected() {
        assert!(HtlcInstruction::unpack(&[]).is_err());
        assert!(HtlcInstruction::unpack(&[9]).is_err(), "unknown tag");
        assert!(
            HtlcInstruction::unpack(&[0, 0, 1, 2, 3]).is_err(),
            "short lock"
        );
        assert!(HtlcInstruction::unpack(&[1, 0, 0]).is_err(), "short claim");
    }
}
