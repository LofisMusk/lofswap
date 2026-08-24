//! Deterministic swap identity, shared with every other leg of a trade.
//!
//! The id commits to the full terms, exactly like the LofSwap chain's own
//! `swap_id`, so a counterparty can recompute it from what they were told and
//! refuse to lock anything if the escrow on this chain says something else.

use solana_program::{hash::hashv, pubkey::Pubkey};

pub const PROTOCOL: &[u8] = b"lofswap-swap-v1";
pub const SWAP_SEED: &[u8] = b"lofswap-htlc";

/// `sha256(secret)` over the raw 32 secret bytes — the same digest the
/// LofSwap chain and the EVM contract compute.
pub fn hashlock_for(secret: &[u8; 32]) -> [u8; 32] {
    hashv(&[secret]).to_bytes()
}

/// Identifier of a swap on this chain.
#[allow(clippy::too_many_arguments)]
pub fn swap_id(
    program_id: &Pubkey,
    maker: &Pubkey,
    recipient: &Pubkey,
    mint: &Pubkey,
    amount: u64,
    hashlock: &[u8; 32],
    timelock: i64,
    nonce: u64,
) -> [u8; 32] {
    hashv(&[
        PROTOCOL,
        b"|solana|",
        program_id.as_ref(),
        maker.as_ref(),
        recipient.as_ref(),
        mint.as_ref(),
        &amount.to_le_bytes(),
        hashlock,
        &timelock.to_le_bytes(),
        &nonce.to_le_bytes(),
    ])
    .to_bytes()
}

/// PDA that owns the escrow, derived from the swap id.
pub fn swap_address(program_id: &Pubkey, swap_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SWAP_SEED, swap_id], program_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashlock_matches_the_cross_chain_test_vector() {
        // The same secret and hashlock the LofSwap node and the EVM contract
        // are pinned to. If this ever changes, the legs stop unlocking each
        // other.
        let secret = [0x9au8; 32];
        let expected =
            hex_to_32("8b9d52fd75ae21d2b827872bd084d762b24fb716dc87974668ecafcfe55df678");
        assert_eq!(hashlock_for(&secret), expected);
    }

    #[test]
    fn swap_id_commits_to_every_term() {
        let program = Pubkey::new_from_array([9u8; 32]);
        let maker = Pubkey::new_from_array([1u8; 32]);
        let recipient = Pubkey::new_from_array([2u8; 32]);
        let mint = Pubkey::new_from_array([3u8; 32]);
        let hashlock = [4u8; 32];
        let base = swap_id(&program, &maker, &recipient, &mint, 10, &hashlock, 100, 0);

        assert_ne!(
            base,
            swap_id(&program, &recipient, &recipient, &mint, 10, &hashlock, 100, 0)
        );
        assert_ne!(
            base,
            swap_id(&program, &maker, &maker, &mint, 10, &hashlock, 100, 0)
        );
        assert_ne!(
            base,
            swap_id(&program, &maker, &recipient, &maker, 10, &hashlock, 100, 0)
        );
        assert_ne!(
            base,
            swap_id(&program, &maker, &recipient, &mint, 11, &hashlock, 100, 0)
        );
        assert_ne!(
            base,
            swap_id(&program, &maker, &recipient, &mint, 10, &[5u8; 32], 100, 0)
        );
        assert_ne!(
            base,
            swap_id(&program, &maker, &recipient, &mint, 10, &hashlock, 101, 0)
        );
        assert_ne!(
            base,
            swap_id(&program, &maker, &recipient, &mint, 10, &hashlock, 100, 1)
        );
    }

    #[test]
    fn swap_address_is_derived_from_the_id() {
        let program = Pubkey::new_from_array([9u8; 32]);
        let (a, bump) = swap_address(&program, &[1u8; 32]);
        let (b, _) = swap_address(&program, &[2u8; 32]);
        assert_ne!(a, b);
        assert_eq!(
            a,
            Pubkey::create_program_address(&[SWAP_SEED, &[1u8; 32], &[bump]], &program).unwrap()
        );
    }

    fn hex_to_32(value: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
}
