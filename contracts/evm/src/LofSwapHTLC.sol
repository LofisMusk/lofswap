// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title LofSwapHTLC — foreign leg of a LofSwap cross-chain atomic swap
/// @notice Hashed timelock escrow for the native coin (ETH, BNB, MATIC, ...)
///         and for any ERC-20 (USDC, USDT, ...). It is the counter-leg to the
///         `SwapLock` / `SwapClaim` / `SwapRefund` transactions on the LofSwap
///         chain and uses the very same secret: a 32-byte preimage whose
///         SHA-256 digest is the hashlock.
/// @dev    Deploy the same bytecode on every EVM chain you want to swap with —
///         Ethereum, BNB Chain, Polygon, Arbitrum, Base, opBNB. Nothing here is
///         chain specific, and `block.chainid` is folded into the swap id so a
///         swap opened on one chain can never be replayed on another.
///
///         Hashlock parity matters: `sha256(abi.encodePacked(secret))` is the
///         same digest LofSwap computes over the raw 32 secret bytes, and the
///         same one Solana's `sha256` syscall produces. Do NOT switch this to
///         keccak256 — the legs would stop unlocking each other.
contract LofSwapHTLC {
    enum State {
        Empty,
        Open,
        Claimed,
        Refunded
    }

    struct Swap {
        address maker;
        address recipient;
        /// address(0) means the chain's native coin.
        address token;
        uint256 amount;
        bytes32 hashlock;
        uint64 timelock;
        /// Swap id of the leg on the other chain (the LofSwap `swap_id`), so
        /// both halves of a trade point at each other on chain.
        bytes32 counterpartyRef;
        State state;
    }

    uint64 public constant MIN_LOCK_SECONDS = 10 minutes;
    uint64 public constant MAX_LOCK_SECONDS = 30 days;

    mapping(bytes32 => Swap) private _swaps;
    /// Per-maker counter that keeps swap ids unique even for identical terms.
    mapping(address => uint256) public nonces;

    event Opened(
        bytes32 indexed id,
        address indexed maker,
        address indexed recipient,
        address token,
        uint256 amount,
        bytes32 hashlock,
        uint64 timelock,
        bytes32 counterpartyRef
    );
    /// @notice Carries the preimage that unlocks the other leg of the trade.
    event Claimed(bytes32 indexed id, address indexed recipient, bytes32 secret);
    event Refunded(bytes32 indexed id, address indexed maker);

    error InvalidRecipient();
    error InvalidAmount();
    error TimelockOutOfRange();
    error NativeValueMismatch();
    error SwapNotOpen();
    error SwapExpired();
    error SwapNotExpired();
    error BadSecret();
    error TransferFailed();

    /// @notice Locks funds under `hashlock` until `timelock`.
    /// @param recipient Address paid when the secret is revealed.
    /// @param token ERC-20 to lock, or address(0) for the native coin.
    /// @param amount Amount to lock; must equal `msg.value` for the native coin.
    /// @param hashlock `sha256(secret)` of the 32-byte preimage.
    /// @param timelock Absolute unix timestamp after which a refund is possible.
    /// @param counterpartyRef Swap id of the leg on the other chain, or zero.
    /// @return id Identifier of the new swap.
    function open(
        address recipient,
        address token,
        uint256 amount,
        bytes32 hashlock,
        uint64 timelock,
        bytes32 counterpartyRef
    ) external payable returns (bytes32 id) {
        if (recipient == address(0) || recipient == msg.sender) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();
        if (
            timelock < block.timestamp + MIN_LOCK_SECONDS
                || timelock > block.timestamp + MAX_LOCK_SECONDS
        ) revert TimelockOutOfRange();

        uint256 locked;
        if (token == address(0)) {
            if (msg.value != amount) revert NativeValueMismatch();
            locked = amount;
        } else {
            if (msg.value != 0) revert NativeValueMismatch();
            // Measure what actually arrived: fee-on-transfer tokens deliver
            // less than `amount`, and the escrow must never promise more than
            // it holds.
            uint256 before = _balanceOf(token, address(this));
            _safeTransferFrom(token, msg.sender, address(this), amount);
            locked = _balanceOf(token, address(this)) - before;
            if (locked == 0) revert InvalidAmount();
        }

        uint256 nonce = nonces[msg.sender]++;
        id = computeId(msg.sender, recipient, token, locked, hashlock, timelock, nonce);

        _swaps[id] = Swap({
            maker: msg.sender,
            recipient: recipient,
            token: token,
            amount: locked,
            hashlock: hashlock,
            timelock: timelock,
            counterpartyRef: counterpartyRef,
            state: State.Open
        });

        emit Opened(id, msg.sender, recipient, token, locked, hashlock, timelock, counterpartyRef);
    }

    /// @notice Releases the escrow to its recipient by revealing the preimage.
    /// @dev Anyone may submit the secret — the funds always go to the recorded
    ///      recipient, so a third party can only pay the gas on their behalf.
    ///      This is what lets a counterparty finish a trade whose recipient has
    ///      gone offline, and it costs nothing: revealing the secret is exactly
    ///      what the recipient wanted to do anyway.
    function claim(bytes32 id, bytes32 secret) external {
        Swap storage swap = _swaps[id];
        if (swap.state != State.Open) revert SwapNotOpen();
        if (block.timestamp >= swap.timelock) revert SwapExpired();
        if (sha256(abi.encodePacked(secret)) != swap.hashlock) revert BadSecret();

        swap.state = State.Claimed;
        emit Claimed(id, swap.recipient, secret);
        _payOut(swap.token, swap.recipient, swap.amount);
    }

    /// @notice Returns an expired escrow to its maker.
    /// @dev Anyone may trigger it; the funds always go back to the maker.
    function refund(bytes32 id) external {
        Swap storage swap = _swaps[id];
        if (swap.state != State.Open) revert SwapNotOpen();
        if (block.timestamp < swap.timelock) revert SwapNotExpired();

        swap.state = State.Refunded;
        emit Refunded(id, swap.maker);
        _payOut(swap.token, swap.maker, swap.amount);
    }

    function getSwap(bytes32 id) external view returns (Swap memory) {
        return _swaps[id];
    }

    /// @notice Recomputes a swap id, so a counterparty can verify the terms of
    ///         a swap before locking their own side.
    function computeId(
        address maker,
        address recipient,
        address token,
        uint256 amount,
        bytes32 hashlock,
        uint64 timelock,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                maker,
                recipient,
                token,
                amount,
                hashlock,
                timelock,
                nonce
            )
        );
    }

    /// @notice The hashlock for a given secret, in the exact form every leg of
    ///         a LofSwap trade expects.
    function hashlockFor(bytes32 secret) external pure returns (bytes32) {
        return sha256(abi.encodePacked(secret));
    }

    function _payOut(address token, address to, uint256 amount) private {
        if (token == address(0)) {
            (bool ok,) = payable(to).call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            _safeTransfer(token, to, amount);
        }
    }

    function _balanceOf(address token, address account) private view returns (uint256) {
        (bool ok, bytes memory data) =
            token.staticcall(abi.encodeWithSelector(0x70a08231, account));
        if (!ok || data.length < 32) revert TransferFailed();
        return abi.decode(data, (uint256));
    }

    function _safeTransfer(address token, address to, uint256 amount) private {
        // transfer(address,uint256)
        _callToken(token, abi.encodeWithSelector(0xa9059cbb, to, amount));
    }

    function _safeTransferFrom(address token, address from, address to, uint256 amount) private {
        // transferFrom(address,address,uint256)
        _callToken(token, abi.encodeWithSelector(0x23b872dd, from, to, amount));
    }

    /// ERC-20 calls go through raw calldata because several major tokens
    /// (USDT among them) return nothing instead of a bool.
    function _callToken(address token, bytes memory payload) private {
        (bool ok, bytes memory data) = token.call(payload);
        // Tokens that return nothing are accepted; tokens that return false
        // are not.
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }
}
