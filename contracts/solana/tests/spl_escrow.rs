//! The SPL token leg (USDC and friends), executed as SBF bytecode against the
//! real SPL token program.

mod common;

use common::*;
use lofswap_htlc_solana::state::{AssetKind, Status};

const USDC: u64 = 1_000_000; // 6 decimals

/// Maker with 100 tokens, an escrow token account owned by the swap PDA, and a
/// token account for the recipient.
struct SplSwap {
    terms: Terms,
    escrow: solana_address::Address,
    mint: solana_address::Address,
    maker_token: solana_address::Address,
    escrow_token: solana_address::Address,
    recipient_token: solana_address::Address,
}

fn spl_swap(env: &mut Env, maker: solana_address::Address, recipient: solana_address::Address, amount: u64) -> SplSwap {
    let mint = env.mint(6);
    let terms = Terms::spl(maker, recipient, mint, amount);
    let escrow = terms.escrow(&env.program);
    SplSwap {
        maker_token: env.token_account(mint, maker, 100 * USDC),
        escrow_token: env.token_account(mint, escrow, 0),
        recipient_token: env.token_account(mint, recipient, 0),
        terms,
        escrow,
        mint,
    }
}

#[test]
fn a_revealed_secret_moves_the_tokens_to_the_recipient() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let relayer = env.funded(SOL);
    let swap = spl_swap(&mut env, maker.pubkey(), recipient.pubkey(), 25 * USDC);

    env.send(
        swap.terms
            .lock_spl(&env.program, swap.maker_token, swap.escrow_token),
        &[&maker],
    )
    .expect("lock");

    assert_eq!(env.token_balance(&swap.escrow_token), 25 * USDC);
    assert_eq!(env.token_balance(&swap.maker_token), 75 * USDC);
    assert_eq!(
        env.balance(&swap.escrow),
        env.state_rent(),
        "an SPL escrow holds no lamports beyond its own rent"
    );
    let locked = env.state(&swap.escrow);
    assert_eq!(locked.asset, AssetKind::SplToken);
    assert_eq!(locked.mint, pk(&swap.mint));
    assert_eq!(locked.escrow_token_account, pk(&swap.escrow_token));
    assert_eq!(locked.amount, 25 * USDC);

    env.send(
        settle_spl(
            &env.program,
            swap.escrow,
            relayer.pubkey(),
            recipient.pubkey(),
            swap.escrow_token,
            swap.recipient_token,
            swap.mint,
            Some(SECRET),
        ),
        &[&relayer],
    )
    .expect("claim");

    assert_eq!(env.token_balance(&swap.recipient_token), 25 * USDC);
    assert_eq!(env.token_balance(&swap.escrow_token), 0);
    let claimed = env.state(&swap.escrow);
    assert_eq!(claimed.status, Status::Claimed);
    assert_eq!(claimed.secret, SECRET);
}

#[test]
fn the_lock_refuses_an_escrow_the_swap_does_not_own() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let thief = env.funded(SOL);
    let swap = spl_swap(&mut env, maker.pubkey(), recipient.pubkey(), 25 * USDC);

    // Same mint, same everything — except the tokens would land somewhere the
    // program cannot claw them back from.
    let thiefs_account = env.token_account(swap.mint, thief.pubkey(), 0);
    rejected(
        env.send(
            swap.terms
                .lock_spl(&env.program, swap.maker_token, thiefs_account),
            &[&maker],
        ),
        "token account has the wrong owner",
    );
    assert_eq!(env.token_balance(&swap.maker_token), 100 * USDC);
}

#[test]
fn the_lock_refuses_an_escrow_holding_a_different_mint() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let swap = spl_swap(&mut env, maker.pubkey(), recipient.pubkey(), 25 * USDC);

    let other_mint = env.mint(6);
    let wrong_escrow = env.token_account(other_mint, swap.escrow, 0);
    rejected(
        env.send(
            swap.terms
                .lock_spl(&env.program, swap.maker_token, wrong_escrow),
            &[&maker],
        ),
        "token account holds the wrong mint",
    );
}

#[test]
fn the_lock_refuses_a_maker_account_that_is_not_a_token_account() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let swap = spl_swap(&mut env, maker.pubkey(), recipient.pubkey(), 25 * USDC);

    rejected(
        env.send(
            swap.terms
                .lock_spl(&env.program, maker.pubkey(), swap.escrow_token),
            &[&maker],
        ),
        "not owned by the token program",
    );
}

#[test]
fn a_claim_cannot_pay_a_token_account_of_somebody_else() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let thief = env.funded(SOL);
    let swap = spl_swap(&mut env, maker.pubkey(), recipient.pubkey(), 25 * USDC);
    env.send(
        swap.terms
            .lock_spl(&env.program, swap.maker_token, swap.escrow_token),
        &[&maker],
    )
    .expect("lock");

    // The beneficiary named in the accounts is the right one, but the token
    // account it would pay into is not theirs.
    let thiefs_account = env.token_account(swap.mint, thief.pubkey(), 0);
    rejected(
        env.send(
            settle_spl(
                &env.program,
                swap.escrow,
                thief.pubkey(),
                recipient.pubkey(),
                swap.escrow_token,
                thiefs_account,
                swap.mint,
                Some(SECRET),
            ),
            &[&thief],
        ),
        "token account has the wrong owner",
    );
    assert_eq!(env.token_balance(&swap.escrow_token), 25 * USDC);
}

#[test]
fn a_claim_cannot_drain_an_escrow_the_swap_never_named() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let swap = spl_swap(&mut env, maker.pubkey(), recipient.pubkey(), 25 * USDC);
    env.send(
        swap.terms
            .lock_spl(&env.program, swap.maker_token, swap.escrow_token),
        &[&maker],
    )
    .expect("lock");

    // A second token account owned by the same PDA — perhaps another swap's
    // escrow. The settlement must only touch the one the lock recorded.
    let other_escrow = env.token_account(swap.mint, swap.escrow, 25 * USDC);
    rejected(
        env.send(
            settle_spl(
                &env.program,
                swap.escrow,
                recipient.pubkey(),
                recipient.pubkey(),
                other_escrow,
                swap.recipient_token,
                swap.mint,
                Some(SECRET),
            ),
            &[&recipient],
        ),
        "InvalidArgument",
    );
    assert_eq!(env.token_balance(&other_escrow), 25 * USDC);
}

#[test]
fn a_refund_returns_the_tokens_to_the_maker_after_the_timelock() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let swap = spl_swap(&mut env, maker.pubkey(), recipient.pubkey(), 25 * USDC);
    env.send(
        swap.terms
            .lock_spl(&env.program, swap.maker_token, swap.escrow_token),
        &[&maker],
    )
    .expect("lock");

    let refund = |env: &Env| {
        settle_spl(
            &env.program,
            swap.escrow,
            maker.pubkey(),
            maker.pubkey(),
            swap.escrow_token,
            swap.maker_token,
            swap.mint,
            None,
        )
    };
    let early = refund(&env);
    rejected(env.send(early, &[&maker]), "swap has not expired yet");

    env.set_time(swap.terms.timelock);
    let due = refund(&env);
    env.send(due, &[&maker]).expect("refund");

    assert_eq!(env.token_balance(&swap.maker_token), 100 * USDC);
    assert_eq!(env.token_balance(&swap.escrow_token), 0);
    assert_eq!(env.state(&swap.escrow).status, Status::Refunded);
}

#[test]
fn close_returns_both_rents_to_the_maker() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let swap = spl_swap(&mut env, maker.pubkey(), recipient.pubkey(), 25 * USDC);
    env.send(
        swap.terms
            .lock_spl(&env.program, swap.maker_token, swap.escrow_token),
        &[&maker],
    )
    .expect("lock");
    env.send(
        settle_spl(
            &env.program,
            swap.escrow,
            recipient.pubkey(),
            recipient.pubkey(),
            swap.escrow_token,
            swap.recipient_token,
            swap.mint,
            Some(SECRET),
        ),
        &[&recipient],
    )
    .expect("claim");

    rejected(
        env.send(
            close_spl(&env.program, swap.escrow, maker.pubkey(), swap.escrow_token),
            &[&maker],
        ),
        "wait for the timelock",
    );

    env.set_time(swap.terms.timelock);
    let expected = env.state_rent() + env.token_rent();
    let before = env.balance(&maker.pubkey());
    env.send(
        close_spl(&env.program, swap.escrow, maker.pubkey(), swap.escrow_token),
        &[&maker],
    )
    .expect("close");

    assert_eq!(env.balance(&maker.pubkey()) - before, expected - FEE);
    assert_eq!(env.balance(&swap.escrow), 0);
    assert!(
        env.account_data(&swap.escrow_token)
            .is_none_or(|data| data.is_empty()),
        "the escrow token account is gone"
    );
}
