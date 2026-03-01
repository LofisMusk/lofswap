struct Counters {
    attempts: atomic<u32>,
    hit_count: atomic<u32>,
}

struct StopFlag {
    value: atomic<u32>,
}

@group(0) @binding(0)
var<storage, read> params: array<u32>; // [start_lo, start_hi, candidate_count, filter_bits, filter_value, max_hits, stop_after_hits]
@group(0) @binding(1)
var<storage, read> base_seed_bytes: array<u32, 32>; // each entry stores one byte in low 8 bits
@group(0) @binding(2)
var<storage, read_write> counters: Counters;
@group(0) @binding(3)
var<storage, read_write> stop_flag: StopFlag;
@group(0) @binding(4)
var<storage, read_write> hit_indices: array<u32>;

fn rotr(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32u - n));
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ ((~x) & z);
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn big_sigma0(x: u32) -> u32 {
    return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
}

fn big_sigma1(x: u32) -> u32 {
    return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
}

fn small_sigma0(x: u32) -> u32 {
    return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
}

fn small_sigma1(x: u32) -> u32 {
    return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
}

var<private> SHA256_K: array<u32, 64> = array<u32, 64>(
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
);

fn sha256_compress(state_in: array<u32, 8>, w_in_ptr: ptr<function, array<u32, 64>>) -> array<u32, 8> {
    var a = state_in[0];
    var b = state_in[1];
    var c = state_in[2];
    var d = state_in[3];
    var e = state_in[4];
    var f = state_in[5];
    var g = state_in[6];
    var h = state_in[7];

    var t = 0u;
    loop {
        if (t >= 64u) {
            break;
        }
        let t1 = h + big_sigma1(e) + ch(e, f, g) + SHA256_K[t] + (*w_in_ptr)[t];
        let t2 = big_sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
        t = t + 1u;
    }

    return array<u32, 8>(
        state_in[0] + a,
        state_in[1] + b,
        state_in[2] + c,
        state_in[3] + d,
        state_in[4] + e,
        state_in[5] + f,
        state_in[6] + g,
        state_in[7] + h
    );
}

fn add_u64_u32(lo: u32, hi: u32, add: u32) -> vec2<u32> {
    let sum_lo = lo + add;
    let carry = select(0u, 1u, sum_lo < lo);
    return vec2<u32>(sum_lo, hi + carry);
}

fn counter_le_byte(counter_lo: u32, counter_hi: u32, idx: u32) -> u32 {
    if (idx < 4u) {
        return (counter_lo >> (idx * 8u)) & 0xffu;
    }
    let shifted = idx - 4u;
    return (counter_hi >> (shifted * 8u)) & 0xffu;
}

fn message_byte(offset: u32, counter_lo: u32, counter_hi: u32) -> u32 {
    if (offset < 32u) {
        return base_seed_bytes[offset] & 0xffu;
    }
    if (offset < 40u) {
        return counter_le_byte(counter_lo, counter_hi, offset - 32u);
    }
    if (offset == 40u) {
        return 0x80u;
    }
    if (offset == 62u) {
        return 0x01u; // length high byte for 320-bit message
    }
    if (offset == 63u) {
        return 0x40u; // length low byte for 320-bit message
    }
    return 0u;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let start_lo = params[0];
    let start_hi = params[1];
    let candidate_count = params[2];
    let filter_bits_raw = params[3];
    let filter_value = params[4];
    let max_hits = params[5];
    let stop_after_hits = params[6];

    let idx = gid.x;
    if (idx >= candidate_count) {
        return;
    }
    if (atomicLoad(&stop_flag.value) != 0u) {
        return;
    }

    atomicAdd(&counters.attempts, 1u);

    let counter = add_u64_u32(start_lo, start_hi, idx);
    let counter_lo = counter.x;
    let counter_hi = counter.y;

    var w: array<u32, 64>;
    var t = 0u;
    loop {
        if (t >= 16u) {
            break;
        }
        let o = t * 4u;
        let b0 = message_byte(o + 0u, counter_lo, counter_hi);
        let b1 = message_byte(o + 1u, counter_lo, counter_hi);
        let b2 = message_byte(o + 2u, counter_lo, counter_hi);
        let b3 = message_byte(o + 3u, counter_lo, counter_hi);
        w[t] = (b0 << 24u) | (b1 << 16u) | (b2 << 8u) | b3;
        t = t + 1u;
    }
    t = 16u;
    loop {
        if (t >= 64u) {
            break;
        }
        w[t] = small_sigma1(w[t - 2u]) + w[t - 7u] + small_sigma0(w[t - 15u]) + w[t - 16u];
        t = t + 1u;
    }

    var state = array<u32, 8>(
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    );
    state = sha256_compress(state, &w);

    var pass = true;
    let filter_bits = min(filter_bits_raw, 32u);
    if (filter_bits > 0u) {
        var mask = 0xffffffffu;
        if (filter_bits < 32u) {
            mask = 0xffffffffu << (32u - filter_bits);
        }
        pass = (state[0] & mask) == (filter_value & mask);
    }

    if (!pass) {
        return;
    }

    let slot = atomicAdd(&counters.hit_count, 1u);
    if (slot < max_hits) {
        hit_indices[slot] = idx;
    }
    if (stop_after_hits > 0u && (slot + 1u) >= stop_after_hits) {
        atomicStore(&stop_flag.value, 1u);
    }
}