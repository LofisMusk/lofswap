//! The native SOL leg, executed as SBF bytecode in the Solana runtime.

mod common;

use common::*;
use lofswap_htlc_solana::{
    state::{AssetKind, Status, STATE_LEN},
    swap_id::hashlock_for,
};

#[test]
fn a_revealed_secret_moves_the_escrow_to_the_recipient() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let relayer = env.funded(SOL);
    let terms = Terms::sol(maker.pubkey(), recipient.pubkey(), 2 * SOL);
    let escrow = terms.escrow(&env.program);
    let rent = env.state_rent();

    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("lock");

    assert_eq!(
        env.balance(&escrow),
        rent + 2 * SOL,
        "the escrow holds the locked amount on top of its rent"
    );
    let locked = env.state(&escrow);
    assert_eq!(locked.status, Status::Open);
    assert_eq!(locked.asset, AssetKind::Sol);
    assert_eq!(locked.maker, pk(&maker.pubkey()));
    assert_eq!(locked.recipient, pk(&recipient.pubkey()));
    assert_eq!(locked.amount, 2 * SOL);
    assert_eq!(locked.hashlock, unhex32(HASHLOCK_HEX));
    assert_eq!(locked.secret, [0u8; 32], "no secret before the claim");
    assert_eq!(locked.swap_id, terms.id(&env.program));

    // Anybody may push the claim; only the recorded recipient may be paid.
    let before = env.balance(&recipient.pubkey());
    env.send(
        settle_sol(
            &env.program,
            escrow,
            relayer.pubkey(),
            recipient.pubkey(),
            Some(SECRET),
        ),
        &[&relayer],
    )
    .expect("claim");

    assert_eq!(
        env.balance(&recipient.pubkey()) - before,
        2 * SOL,
        "the recipient is paid in full, and pays no fee for it"
    );
    assert_eq!(env.balance(&escrow), rent, "only the rent stays behind");
    let claimed = env.state(&escrow);
    assert_eq!(claimed.status, Status::Claimed);
    assert_eq!(claimed.secret, SECRET, "the preimage is published on chain");
}

#[test]
fn the_claim_logs_the_preimage_for_the_other_leg() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);
    let escrow = terms.escrow(&env.program);

    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("lock");
    let meta = env
        .send(
            settle_sol(
                &env.program,
                escrow,
                recipient.pubkey(),
                recipient.pubkey(),
                Some(SECRET),
            ),
            &[&recipient],
        )
        .expect("claim");

    let secret = hex32(&SECRET);
    assert!(
        meta.logs.iter().any(|line| line.contains(&secret)),
        "the counterparty must be able to lift the secret out of the transaction:\n{}",
        meta.pretty_logs()
    );
}

#[test]
fn the_hashlock_is_the_one_every_leg_is_pinned_to() {
    // Locking with the shared test vector and claiming with the raw 32 bytes
    // is what keeps the LofSwap, EVM and Solana legs unlocking each other.
    assert_eq!(hex32(&hashlock_for(&SECRET)), HASHLOCK_HEX);

    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let mut terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);
    terms.hashlock = unhex32(HASHLOCK_HEX);
    let escrow = terms.escrow(&env.program);

    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("lock");
    env.send(
        settle_sol(
            &env.program,
            escrow,
            recipient.pubkey(),
            recipient.pubkey(),
            Some(SECRET),
        ),
        &[&recipient],
    )
    .expect("the pinned secret must open the pinned hashlock");
}

#[test]
fn a_wrong_secret_claims_nothing() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);
    let escrow = terms.escrow(&env.program);
    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("lock");

    rejected(
        env.send(
            settle_sol(
                &env.program,
                escrow,
                recipient.pubkey(),
                recipient.pubkey(),
                Some([0x9b; 32]),
            ),
            &[&recipient],
        ),
        "secret does not match the hashlock",
    );
    assert_eq!(env.state(&escrow).status, Status::Open);
}

#[test]
fn knowing_the_secret_does_not_let_a_thief_redirect_the_payout() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let thief = env.funded(SOL);
    let terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);
    let escrow = terms.escrow(&env.program);
    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("lock");

    // The secret is public the moment the other leg settles; it must still be
    // useless to anybody but the recipient named in the lock.
    rejected(
        env.send(
            settle_sol(
                &env.program,
                escrow,
                thief.pubkey(),
                thief.pubkey(),
                Some(SECRET),
            ),
            &[&thief],
        ),
        "a claim must pay the recipient",
    );
    assert_eq!(env.balance(&escrow), env.state_rent() + SOL);
}

#[test]
fn the_claim_window_closes_at_the_timelock() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);
    let escrow = terms.escrow(&env.program);
    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("lock");

    env.set_time(terms.timelock);
    rejected(
        env.send(
            settle_sol(
                &env.program,
                escrow,
                recipient.pubkey(),
                recipient.pubkey(),
                Some(SECRET),
            ),
            &[&recipient],
        ),
        "claim window closed",
    );
}

#[test]
fn a_refund_waits_for_the_timelock_and_pays_the_maker() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let thief = env.funded(SOL);
    let terms = Terms::sol(maker.pubkey(), recipient.pubkey(), 3 * SOL);
    let escrow = terms.escrow(&env.program);
    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("lock");

    rejected(
        env.send(
            settle_sol(&env.program, escrow, maker.pubkey(), maker.pubkey(), None),
            &[&maker],
        ),
        "swap has not expired yet",
    );

    env.set_time(terms.timelock);
    rejected(
        env.send(
            settle_sol(&env.program, escrow, thief.pubkey(), thief.pubkey(), None),
            &[&thief],
        ),
        "a refund must pay the maker",
    );

    let before = env.balance(&maker.pubkey());
    env.send(
        settle_sol(&env.program, escrow, maker.pubkey(), maker.pubkey(), None),
        &[&maker],
    )
    .expect("refund");
    assert_eq!(
        env.balance(&maker.pubkey()) - before,
        3 * SOL - FEE,
        "the maker gets the locked amount back, less the transaction fee"
    );
    assert_eq!(env.state(&escrow).status, Status::Refunded);
}

#[test]
fn a_settled_swap_cannot_be_settled_again() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);
    let escrow = terms.escrow(&env.program);
    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("lock");
    env.send(
        settle_sol(
            &env.program,
            escrow,
            recipient.pubkey(),
            recipient.pubkey(),
            Some(SECRET),
        ),
        &[&recipient],
    )
    .expect("claim");

    rejected(
        env.send(
            settle_sol(
                &env.program,
                escrow,
                recipient.pubkey(),
                recipient.pubkey(),
                Some(SECRET),
            ),
            &[&recipient],
        ),
        "swap is already settled",
    );

    // …and a claimed swap can never be refunded out from under the recipient.
    env.set_time(terms.timelock);
    rejected(
        env.send(
            settle_sol(&env.program, escrow, maker.pubkey(), maker.pubkey(), None),
            &[&maker],
        ),
        "swap is already settled",
    );
    assert_eq!(env.balance(&escrow), env.state_rent());
}

#[test]
fn the_lock_enforces_the_documented_timelock_window() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);

    for (offset, what) in [(9 * 60, "too soon"), (30 * DAY + 1, "too far out")] {
        let mut terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);
        terms.timelock = NOW + offset;
        rejected(
            env.send(terms.lock_sol(&env.program), &[&maker]),
            "timelock must be",
        );
        assert!(
            env.account_data(&terms.escrow(&env.program)).is_none(),
            "nothing should be locked with a timelock that is {what}"
        );
    }

    // The bounds themselves are usable.
    for offset in [10 * 60, 30 * DAY] {
        let mut terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);
        terms.timelock = NOW + offset;
        env.send(terms.lock_sol(&env.program), &[&maker])
            .unwrap_or_else(|err| panic!("{offset}s should be inside the window: {err:?}"));
    }
}

#[test]
fn the_lock_rejects_terms_that_could_freeze_or_waste_coins() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);

    let mut empty = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);
    empty.amount = 0;
    rejected(
        env.send(empty.lock_sol(&env.program), &[&maker]),
        "InvalidArgument",
    );

    let to_self = Terms::sol(maker.pubkey(), maker.pubkey(), SOL);
    rejected(
        env.send(to_self.lock_sol(&env.program), &[&maker]),
        "recipient must be somebody else",
    );
}

#[test]
fn the_same_terms_cannot_be_locked_twice() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);

    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("lock");
    rejected(
        env.send(terms.lock_sol(&env.program), &[&maker]),
        "this swap already exists",
    );

    // A different nonce is a different swap, and gets its own escrow.
    let mut again = terms.clone();
    again.nonce = 1;
    assert_ne!(again.escrow(&env.program), terms.escrow(&env.program));
    env.send(again.lock_sol(&env.program), &[&maker])
        .expect("a fresh nonce is a fresh swap");
}

#[test]
fn the_escrow_address_has_to_be_the_one_the_terms_derive() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);

    // An escrow derived from *different* terms — the counterparty's check that
    // the escrow address matches what they were promised is what this protects.
    let mut other = terms.clone();
    other.amount = 2 * SOL;
    rejected(
        env.send(
            terms.lock_sol_into(&env.program, other.escrow(&env.program)),
            &[&maker],
        ),
        "does not match the swap terms",
    );
}

#[test]
fn an_escrow_address_somebody_prefunded_is_still_usable() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);
    let escrow = terms.escrow(&env.program);

    // Griefing attempt: park lamports on the escrow address before the maker
    // gets to it, so `create_account` would fail on it forever. The program
    // transfers/allocates/assigns instead, so the swap still opens and the
    // squatted lamports simply count towards what the maker owes.
    let squatted = env.svm.minimum_balance_for_rent_exemption(0);
    env.svm.airdrop(&escrow, squatted).unwrap();
    let maker_before = env.balance(&maker.pubkey());

    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("a squatted escrow address must not brick the swap");

    let rent = env.state_rent();
    assert_eq!(env.balance(&escrow), rent + SOL);
    assert_eq!(
        maker_before - env.balance(&maker.pubkey()),
        rent + SOL - squatted + FEE,
        "the maker only tops the escrow up to what the swap needs"
    );
}

#[test]
fn close_returns_the_rent_once_the_secret_has_had_its_day() {
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let stranger = env.funded(SOL);
    let terms = Terms::sol(maker.pubkey(), recipient.pubkey(), SOL);
    let escrow = terms.escrow(&env.program);
    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("lock");

    rejected(
        env.send(close(&env.program, escrow, maker.pubkey()), &[&maker]),
        "swap is still open",
    );

    env.send(
        settle_sol(
            &env.program,
            escrow,
            recipient.pubkey(),
            recipient.pubkey(),
            Some(SECRET),
        ),
        &[&recipient],
    )
    .expect("claim");

    // Until the timelock passes the record stays readable for the counterparty.
    rejected(
        env.send(close(&env.program, escrow, maker.pubkey()), &[&maker]),
        "wait for the timelock",
    );
    assert_eq!(env.state(&escrow).secret, SECRET);

    env.set_time(terms.timelock);
    rejected(
        env.send(close(&env.program, escrow, stranger.pubkey()), &[&stranger]),
        "InvalidArgument",
    );

    let rent = env.state_rent();
    let before = env.balance(&maker.pubkey());
    env.send(close(&env.program, escrow, maker.pubkey()), &[&maker])
        .expect("close");
    assert_eq!(env.balance(&maker.pubkey()) - before, rent - FEE);
    assert_eq!(env.balance(&escrow), 0);
}

#[test]
fn the_escrow_account_decodes_from_the_documented_offsets() {
    // The layout is the client ABI: any language should be able to read a swap
    // out of the account with a fixed offset table.
    let mut env = Env::new();
    let maker = env.funded(10 * SOL);
    let recipient = env.funded(SOL);
    let mut terms = Terms::sol(maker.pubkey(), recipient.pubkey(), 7 * SOL);
    terms.nonce = 42;
    terms.counterparty_ref = [0xab; 32];
    let escrow = terms.escrow(&env.program);
    env.send(terms.lock_sol(&env.program), &[&maker])
        .expect("lock");

    let data = env.account_data(&escrow).expect("escrow account");
    assert_eq!(data.len(), STATE_LEN);
    assert_eq!(&data[0..8], b"LOFSWAP1");
    assert_eq!(data[8], 1, "state version");
    assert_eq!(data[9], Status::Open as u8);
    assert_eq!(data[10], AssetKind::Sol as u8);
    assert_eq!(&data[11..43], &terms.id(&env.program));
    assert_eq!(&data[43..75], &maker.pubkey().to_bytes());
    assert_eq!(&data[75..107], &recipient.pubkey().to_bytes());
    assert_eq!(&data[107..139], &[0u8; 32], "no mint for a SOL swap");
    assert_eq!(&data[139..171], &[0u8; 32], "no escrow token account");
    assert_eq!(u64::from_le_bytes(data[171..179].try_into().unwrap()), 7 * SOL);
    assert_eq!(&data[179..211], &unhex32(HASHLOCK_HEX));
    assert_eq!(
        i64::from_le_bytes(data[211..219].try_into().unwrap()),
        terms.timelock
    );
    assert_eq!(u64::from_le_bytes(data[219..227].try_into().unwrap()), 42);
    assert_eq!(&data[227..259], &[0xab; 32], "counterparty reference");
    assert_eq!(&data[259..291], &[0u8; 32], "secret still hidden");
}
