use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use bip39::{Language, Mnemonic};
use blockchain_core::{
    CHAIN_ID, pubkey_to_address,
    wallet_keystore::{
        DEFAULT_DERIVATION_PATH, derive_secret_key_from_mnemonic, generate_mnemonic_12,
    },
};
use hkdf::Hkdf;
use rand::rand_core::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use wgpu::DeviceType as WgpuDeviceType;

use crate::gpu::{
    GPU_PUBKEY_SHA256_ASCII_LEN, GpuAdapterSummary, GpuComputeRuntime, GpuPayloadBatchFilterConfig,
    GpuPayloadBatchFilterSession, GpuPubkeySha256Session, GpuRawVanityBatchConfig,
    GpuRawVanitySession, gpu_filter_payload_batch, list_gpu_adapters, select_best_gpu_adapter,
};
use crate::opencl::{OpenClDeviceSummary, list_opencl_devices, select_best_opencl_device};

const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const VANITY_ATTEMPT_RESERVATION_CHUNK: u64 = 256;
const RAW_GPU_FILTER_BITS: u32 = 12;
const RAW_CPU_ADDRESS_FILTER_BITS: u32 = 8;
const RAW_GPU_MAX_HITS_PER_BATCH: u32 = 4096;

fn valid_vanity_pattern(pattern: &str) -> bool {
    !pattern.is_empty() && pattern.chars().all(|c| BASE58_ALPHABET.contains(c))
}

fn format_attempt_rate_per_sec(rate: f64) -> String {
    if !rate.is_finite() || rate <= 0.0 {
        "0.00/s".to_string()
    } else if rate >= 1_000_000_000.0 {
        format!("{:.2} G/s", rate / 1_000_000_000.0)
    } else if rate >= 1_000_000.0 {
        format!("{:.2} M/s", rate / 1_000_000.0)
    } else if rate >= 1_000.0 {
        format!("{:.2} K/s", rate / 1_000.0)
    } else {
        format!("{:.2}/s", rate)
    }
}

pub(crate) fn address_matches_vanity(
    address: &str,
    starts_with: Option<&str>,
    ends_with: Option<&str>,
) -> bool {
    let payload = address.strip_prefix("LFS").unwrap_or(address);
    if let Some(prefix) = starts_with {
        if !payload.starts_with(prefix) {
            return false;
        }
    }
    if let Some(suffix) = ends_with {
        if !payload.ends_with(suffix) {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VanityComputeMode {
    Cpu,
    Gpu,
    OpenCl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VanitySource {
    Raw,
    Mnemonic,
}

impl VanitySource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Mnemonic => "mnemonic",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreateWalletOptions {
    pub(crate) starts_with: Option<String>,
    pub(crate) ends_with: Option<String>,
    pub(crate) compute_mode: VanityComputeMode,
    pub(crate) worker_count: Option<usize>,
    pub(crate) vanity_source: VanitySource,
    pub(crate) generate_mnemonic_after_hit: bool,
}

impl Default for CreateWalletOptions {
    fn default() -> Self {
        Self {
            starts_with: None,
            ends_with: None,
            compute_mode: VanityComputeMode::Cpu,
            worker_count: None,
            vanity_source: VanitySource::Mnemonic,
            generate_mnemonic_after_hit: false,
        }
    }
}

pub(crate) fn parse_vanity_args(args: &[&str]) -> Result<CreateWalletOptions, String> {
    if args.is_empty() {
        return Ok(CreateWalletOptions::default());
    }

    let mut parsed = CreateWalletOptions::default();
    let mut compute_mode_seen = false;
    let mut vanity_source_override: Option<VanitySource> = None;
    let mut i = 0usize;
    while i < args.len() {
        let key = args[i].to_ascii_lowercase();
        match key.as_str() {
            "--generate-mnemonic-after-hit" => {
                parsed.generate_mnemonic_after_hit = true;
                i += 1;
            }
            "--vanity-source" => {
                let value = args
                    .get(i + 1)
                    .map(|v| v.trim().to_ascii_lowercase())
                    .ok_or_else(|| "Missing value for --vanity-source".to_string())?;
                vanity_source_override = match value.as_str() {
                    "raw" => Some(VanitySource::Raw),
                    "mnemonic" => Some(VanitySource::Mnemonic),
                    _ => {
                        return Err(format!(
                            "Invalid vanity source '{}'. Use raw or mnemonic.",
                            value
                        ));
                    }
                };
                i += 2;
            }
            _ if key.starts_with("--vanity-source=") => {
                let value = key.trim_start_matches("--vanity-source=");
                vanity_source_override = match value {
                    "raw" => Some(VanitySource::Raw),
                    "mnemonic" => Some(VanitySource::Mnemonic),
                    _ => {
                        return Err(format!(
                            "Invalid vanity source '{}'. Use raw or mnemonic.",
                            value
                        ));
                    }
                };
                i += 1;
            }
            "startswith" => {
                let value = args
                    .get(i + 1)
                    .map(|v| v.trim())
                    .ok_or_else(|| "Missing value for startswith".to_string())?;
                if value.is_empty() {
                    return Err("Vanity value cannot be empty".to_string());
                }
                if parsed.starts_with.is_some() {
                    return Err("Duplicate startswith argument".to_string());
                }
                if !valid_vanity_pattern(value) {
                    return Err(format!(
                        "Invalid vanity pattern '{}'. Use Base58 chars only.",
                        value
                    ));
                }
                parsed.starts_with = Some(value.to_string());
                i += 2;
            }
            "endswith" => {
                let value = args
                    .get(i + 1)
                    .map(|v| v.trim())
                    .ok_or_else(|| "Missing value for endswith".to_string())?;
                if value.is_empty() {
                    return Err("Vanity value cannot be empty".to_string());
                }
                if parsed.ends_with.is_some() {
                    return Err("Duplicate endswith argument".to_string());
                }
                if !valid_vanity_pattern(value) {
                    return Err(format!(
                        "Invalid vanity pattern '{}'. Use Base58 chars only.",
                        value
                    ));
                }
                parsed.ends_with = Some(value.to_string());
                i += 2;
            }
            "cpu" | "gpu" | "opencl" => {
                if compute_mode_seen {
                    return Err("Duplicate compute mode/worker-count argument".to_string());
                }
                compute_mode_seen = true;
                parsed.compute_mode = match key.as_str() {
                    "gpu" => VanityComputeMode::Gpu,
                    "opencl" => VanityComputeMode::OpenCl,
                    _ => VanityComputeMode::Cpu,
                };
                let next = args.get(i + 1).map(|v| v.trim());
                let next_is_key = next
                    .map(|v| {
                        matches!(
                            v.to_ascii_lowercase().as_str(),
                            "startswith"
                                | "endswith"
                                | "cpu"
                                | "gpu"
                                | "opencl"
                                | "--vanity-source"
                                | "--generate-mnemonic-after-hit"
                        ) || v.to_ascii_lowercase().starts_with("--vanity-source=")
                    })
                    .unwrap_or(false);
                if let Some(value) = next {
                    if value.is_empty() {
                        return Err("Worker count must be a positive integer".to_string());
                    }
                    if !next_is_key {
                        let workers = value
                            .parse::<usize>()
                            .ok()
                            .filter(|n| *n > 0)
                            .ok_or_else(|| "Worker count must be a positive integer".to_string())?;
                        parsed.worker_count = Some(workers);
                        i += 2;
                        continue;
                    }
                }
                i += 1;
            }
            _ => {
                return Err(format!(
                    "Unknown argument '{}'. Use startswith/endswith/cpu/gpu/opencl/--vanity-source/--generate-mnemonic-after-hit.",
                    args[i]
                ));
            }
        }
    }
    parsed.vanity_source = vanity_source_override.unwrap_or_else(|| {
        if parsed.compute_mode == VanityComputeMode::Gpu {
            VanitySource::Raw
        } else {
            VanitySource::Mnemonic
        }
    });
    Ok(parsed)
}

pub(crate) fn default_cpu_workers() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}

#[derive(Debug)]
pub(crate) struct VanityMatch {
    pub(crate) sk: SecretKey,
    pub(crate) mnemonic: Option<String>,
    pub(crate) public_key: String,
    pub(crate) address: String,
    pub(crate) attempts: u64,
}

#[derive(Debug)]
struct GpuHybridCandidate {
    sk: SecretKey,
    mnemonic: Mnemonic,
    attempts: u64,
}

fn hkdf_salt_for_wallet_derivation() -> String {
    format!("{}|{}", CHAIN_ID, DEFAULT_DERIVATION_PATH)
}

fn generate_mnemonic_12_fast<R: Rng + ?Sized>(rng: &mut R) -> Result<Mnemonic, String> {
    let mut entropy = [0u8; 16];
    rng.fill_bytes(&mut entropy);
    Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| format!("mnemonic generation failed: {}", e))
}

fn derive_secret_key_from_mnemonic_fast(
    mnemonic: &Mnemonic,
    mnemonic_passphrase: &str,
    hkdf_salt: &str,
) -> Result<[u8; 32], String> {
    let seed = mnemonic.to_seed_normalized(mnemonic_passphrase);
    let hkdf = Hkdf::<Sha256>::new(Some(hkdf_salt.as_bytes()), &seed);
    let mut out = [0u8; 32];
    hkdf.expand(b"lofswap-wallet-secp256k1", &mut out)
        .map_err(|_| "hkdf derivation failed".to_string())?;
    if out.iter().all(|b| *b == 0) {
        out[31] = 1;
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
struct RawFastFilter {
    bits: u32,
    value: u32,
}

fn deterministic_raw_base_seed(starts_with: Option<&str>, ends_with: Option<&str>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"lofswap-vanity-raw-seed-v1");
    hasher.update(CHAIN_ID.as_bytes());
    if let Some(prefix) = starts_with {
        hasher.update(b"|prefix|");
        hasher.update(prefix.as_bytes());
    }
    if let Some(suffix) = ends_with {
        hasher.update(b"|suffix|");
        hasher.update(suffix.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn raw_filter_value_from_context(
    label: &[u8],
    base_seed: &[u8; 32],
    starts_with: Option<&str>,
    ends_with: Option<&str>,
) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(base_seed);
    if let Some(prefix) = starts_with {
        hasher.update(prefix.as_bytes());
    }
    if let Some(suffix) = ends_with {
        hasher.update(suffix.as_bytes());
    }
    let digest = hasher.finalize();
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn deterministic_raw_private_key(base_seed: &[u8; 32], counter: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(base_seed);
    hasher.update(counter.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn address_bytes_from_public_key(public_key: &str) -> [u8; 20] {
    let digest = Sha256::digest(public_key.as_bytes());
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

fn raw_bytes_fast_filter_matches(bytes: &[u8], filter: RawFastFilter) -> bool {
    if filter.bits == 0 {
        return true;
    }
    let bits = filter.bits.min(32);
    if bytes.len() < 4 {
        return false;
    }
    let head = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mask = if bits == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - bits)
    };
    (head & mask) == (filter.value & mask)
}

#[derive(Debug, Clone)]
pub(crate) struct VanitySearchRequest {
    pub(crate) starts_with: Option<String>,
    pub(crate) ends_with: Option<String>,
    pub(crate) tries_limit: u64,
    pub(crate) mnemonic_pwd: String,
    pub(crate) cpu_workers: usize,
    pub(crate) vanity_source: VanitySource,
}

#[derive(Debug, Clone)]
pub(crate) enum VanitySearchBackend {
    Cpu {
        worker_count: usize,
    },
    Gpu {
        requested_workers: usize,
        selected_adapter: Option<GpuAdapterSummary>,
        fallback_reason: String,
    },
    OpenCl {
        requested_workers: usize,
        selected_device: Option<OpenClDeviceSummary>,
        fallback_reason: String,
    },
}

impl VanitySearchBackend {
    pub(crate) fn prepare(mode: VanityComputeMode, requested_workers: usize) -> Self {
        match mode {
            VanityComputeMode::Cpu => Self::Cpu {
                worker_count: requested_workers.max(1),
            },
            VanityComputeMode::Gpu => {
                let adapters = list_gpu_adapters();
                if adapters.is_empty() {
                    return Self::Gpu {
                        requested_workers: requested_workers.max(1),
                        selected_adapter: None,
                        fallback_reason: "No GPU adapters detected by wgpu; using CPU workers."
                            .to_string(),
                    };
                }

                if let Some(best) = select_best_gpu_adapter(&adapters) {
                    if best.device_type == WgpuDeviceType::Cpu {
                        return Self::Gpu {
                            requested_workers: requested_workers.max(1),
                            selected_adapter: None,
                            fallback_reason:
                                "Only CPU/software adapters detected; using CPU workers."
                                    .to_string(),
                        };
                    }
                    Self::Gpu {
                        requested_workers: requested_workers.max(1),
                        selected_adapter: Some(best),
                        fallback_reason:
                            "GPU vanity backend enabled (wgpu compute). Will fall back to CPU search only if GPU runtime/setup fails."
                                .to_string(),
                    }
                } else {
                    Self::Gpu {
                        requested_workers: requested_workers.max(1),
                        selected_adapter: None,
                        fallback_reason: "Only CPU/software adapters detected; using CPU workers."
                            .to_string(),
                    }
                }
            }
            VanityComputeMode::OpenCl => match list_opencl_devices() {
                Ok(devices) if devices.is_empty() => Self::OpenCl {
                    requested_workers: requested_workers.max(1),
                    selected_device: None,
                    fallback_reason: "No OpenCL devices detected; using CPU workers.".to_string(),
                },
                Ok(devices) => {
                    if let Some(best) = select_best_opencl_device(&devices) {
                        Self::OpenCl {
                            requested_workers: requested_workers.max(1),
                            selected_device: Some(best),
                            fallback_reason:
                                "OpenCL vanity backend selected (scaffolded). Will fall back to CPU until OpenCL vanity kernels are implemented."
                                    .to_string(),
                        }
                    } else {
                        Self::OpenCl {
                            requested_workers: requested_workers.max(1),
                            selected_device: None,
                            fallback_reason:
                                "No suitable OpenCL device selected; using CPU workers.".to_string(),
                        }
                    }
                }
                Err(err) => Self::OpenCl {
                    requested_workers: requested_workers.max(1),
                    selected_device: None,
                    fallback_reason: format!("OpenCL unavailable ({}); using CPU workers.", err),
                },
            },
        }
    }

    fn effective_cpu_workers(&self) -> usize {
        match self {
            Self::Cpu { worker_count } => *worker_count,
            Self::Gpu {
                requested_workers, ..
            } => *requested_workers,
            Self::OpenCl {
                requested_workers, ..
            } => *requested_workers,
        }
    }

    pub(crate) fn mode_label(&self) -> &'static str {
        match self {
            Self::Cpu { .. } => "cpu",
            Self::Gpu { .. } => "gpu",
            Self::OpenCl { .. } => "opencl",
        }
    }

    pub(crate) fn print_preflight(&self) {
        match self {
            Self::Gpu {
                selected_adapter,
                fallback_reason,
                ..
            } => {
                if let Some(best) = selected_adapter {
                    println!(
                        "Selected GPU adapter: {} | vendor={} (0x{:04x}) | type={:?} | backend={:?}",
                        best.name, best.vendor_name, best.vendor, best.device_type, best.backend
                    );
                    if !best.driver.is_empty() {
                        println!("GPU driver: {}", best.driver);
                    }
                }
                println!("{}", fallback_reason);
            }
            Self::OpenCl {
                selected_device,
                fallback_reason,
                ..
            } => {
                if let Some(best) = selected_device {
                    println!(
                        "Selected OpenCL device: {} | vendor={} | type={} | CU={} | clock={}MHz | mem={} MiB",
                        best.name,
                        best.vendor,
                        best.device_type_label,
                        best.max_compute_units,
                        best.max_clock_mhz,
                        best.global_mem_mib
                    );
                    println!(
                        "OpenCL platform: {} | vendor={}",
                        best.platform_name, best.platform_vendor
                    );
                    if !best.driver_version.is_empty() {
                        println!("OpenCL driver: {}", best.driver_version);
                    }
                    if !best.version.is_empty() {
                        println!("OpenCL version: {}", best.version);
                    }
                }
                println!("{}", fallback_reason);
            }
            Self::Cpu { .. } => {}
        }
    }
}

pub(crate) fn run_vanity_search(
    request: &VanitySearchRequest,
    backend: &VanitySearchBackend,
) -> Result<Option<VanityMatch>, String> {
    match request.vanity_source {
        VanitySource::Mnemonic => run_vanity_search_mnemonic(request, backend),
        VanitySource::Raw => run_vanity_search_raw(request, backend),
    }
}

fn run_vanity_search_mnemonic(
    request: &VanitySearchRequest,
    backend: &VanitySearchBackend,
) -> Result<Option<VanityMatch>, String> {
    if let VanitySearchBackend::OpenCl {
        selected_device: Some(_),
        ..
    } = backend
    {
        println!(
            "OpenCL vanity backend is scaffolded, but OpenCL vanity kernels are not implemented yet. Continuing with CPU fallback."
        );
    }

    if let VanitySearchBackend::Gpu {
        requested_workers,
        selected_adapter,
        ..
    } = backend
    {
        if selected_adapter.is_some() {
            let sample_target = (*requested_workers).clamp(1, 256).saturating_mul(64);
            let (payloads, cpu_matches) = build_real_address_payload_preflight_batch(
                sample_target,
                &request.mnemonic_pwd,
                request.starts_with.as_deref(),
                request.ends_with.as_deref(),
            );
            if payloads.is_empty() {
                println!("GPU preflight skipped: could not build real-address sample batch.");
            } else {
                let filter_config = GpuPayloadBatchFilterConfig {
                    prefix: request.starts_with.clone(),
                    suffix: request.ends_with.clone(),
                    max_hits: 32,
                    stop_after_hits: 8,
                };
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    gpu_filter_payload_batch(None, &payloads, &filter_config)
                })) {
                    Ok(Ok(result)) => {
                        println!(
                            "GPU real-address preflight summary: batch={} gpu_candidate_count={} attempts={} prefix_hits={} suffix_hits={} cpu_matches={} gpu_combined_hits={} hit_count={} stored_hits={} verified_hits={} mismatches={} stop_flag={} elapsed={:.3}s",
                            payloads.len(),
                            result.candidate_count,
                            result.attempts,
                            result.prefix_hits,
                            result.suffix_hits,
                            cpu_matches,
                            result.combined_hits,
                            result.hit_count,
                            result.stored_hit_indices.len(),
                            result.verified_stored_hits,
                            result.verification_mismatches,
                            result.stop_flag_triggered,
                            result.elapsed.as_secs_f64()
                        );
                        if result.combined_hits != cpu_matches as u64 {
                            println!(
                                "Warning: GPU/CPU preflight hit-count mismatch (gpu={}, cpu={})",
                                result.combined_hits, cpu_matches
                            );
                        }
                    }
                    Ok(Err(err)) => {
                        println!(
                            "GPU real-address preflight failed (continuing with CPU fallback): {}",
                            err
                        );
                    }
                    Err(_) => {
                        println!(
                            "GPU real-address preflight panicked (continuing with CPU fallback)."
                        );
                    }
                }
            }

            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                find_vanity_wallet_gpu_hybrid(
                    request.starts_with.as_deref(),
                    request.ends_with.as_deref(),
                    request.tries_limit,
                    &request.mnemonic_pwd,
                    *requested_workers,
                )
            })) {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(err)) => {
                    println!(
                        "GPU hybrid search failed (continuing with CPU fallback): {}",
                        err
                    );
                }
                Err(_) => {
                    println!("GPU hybrid search panicked (continuing with CPU fallback).");
                }
            }
        }
    }

    find_vanity_wallet_mnemonic_parallel(
        request.starts_with.as_deref(),
        request.ends_with.as_deref(),
        request.tries_limit,
        &request.mnemonic_pwd,
        backend.effective_cpu_workers(),
    )
}

fn run_vanity_search_raw(
    request: &VanitySearchRequest,
    backend: &VanitySearchBackend,
) -> Result<Option<VanityMatch>, String> {
    let starts_with = request.starts_with.as_deref();
    let ends_with = request.ends_with.as_deref();
    let base_seed = deterministic_raw_base_seed(starts_with, ends_with);
    let gpu_filter = RawFastFilter {
        bits: RAW_GPU_FILTER_BITS,
        value: raw_filter_value_from_context(
            b"lofswap-raw-gpu-filter-v1",
            &base_seed,
            starts_with,
            ends_with,
        ),
    };
    let cpu_address_filter = RawFastFilter {
        bits: RAW_CPU_ADDRESS_FILTER_BITS,
        value: raw_filter_value_from_context(
            b"lofswap-raw-cpu-address-filter-v1",
            &base_seed,
            starts_with,
            ends_with,
        ),
    };

    println!(
        "RAW vanity source enabled (deterministic SHA256(seed||counter)); base_seed={}..., gpu_filter_bits={}, cpu_address_filter_bits={}",
        hex::encode(&base_seed[..8]),
        gpu_filter.bits,
        cpu_address_filter.bits
    );

    if let VanitySearchBackend::OpenCl {
        selected_device: Some(_),
        ..
    } = backend
    {
        println!(
            "OpenCL vanity backend is scaffolded, but OpenCL vanity kernels are not implemented yet. Continuing with CPU fallback."
        );
    }

    if let VanitySearchBackend::Gpu {
        requested_workers,
        selected_adapter,
        ..
    } = backend
    {
        if selected_adapter.is_some() {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                find_vanity_wallet_gpu_raw(
                    starts_with,
                    ends_with,
                    request.tries_limit,
                    base_seed,
                    gpu_filter,
                    cpu_address_filter,
                    *requested_workers,
                )
            })) {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(err)) => {
                    println!(
                        "GPU raw vanity search failed (continuing with CPU fallback): {}",
                        err
                    );
                }
                Err(_) => {
                    println!("GPU raw vanity search panicked (continuing with CPU fallback).");
                }
            }
        }
    }

    find_vanity_wallet_raw_parallel(
        starts_with,
        ends_with,
        request.tries_limit,
        base_seed,
        cpu_address_filter,
        backend.effective_cpu_workers(),
    )
}

fn build_real_address_payload_preflight_batch(
    target_count: usize,
    mnemonic_pwd: &str,
    starts_with: Option<&str>,
    ends_with: Option<&str>,
) -> (Vec<String>, usize) {
    let target_count = target_count.clamp(32, 2048);
    let mut payloads = Vec::with_capacity(target_count);
    let mut attempts = 0usize;
    let max_attempts = target_count.saturating_mul(4).max(64);

    while payloads.len() < target_count && attempts < max_attempts {
        attempts += 1;
        let Ok(mnemonic) = generate_mnemonic_12() else {
            continue;
        };
        let Ok(derived) =
            derive_secret_key_from_mnemonic(&mnemonic, mnemonic_pwd, DEFAULT_DERIVATION_PATH)
        else {
            continue;
        };
        let Ok(sk) = SecretKey::from_byte_array(derived) else {
            continue;
        };
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let address = pubkey_to_address(&pk.to_string());
        let payload = address.strip_prefix("LFS").unwrap_or(&address).to_string();
        if payload.is_ascii() {
            payloads.push(payload);
        }
    }

    // CPU reference count on the exact same batch that will be sent to GPU filter.
    // (Matching is on payload because `address_matches_vanity` strips "LFS".)
    let cpu_matches = payloads
        .iter()
        .filter(|payload| payload_matches_vanity_filters(payload, starts_with, ends_with))
        .count();
    (payloads, cpu_matches)
}

fn payload_matches_vanity_filters(
    payload: &str,
    starts_with: Option<&str>,
    ends_with: Option<&str>,
) -> bool {
    if let Some(prefix) = starts_with {
        if !payload.starts_with(prefix) {
            return false;
        }
    }
    if let Some(suffix) = ends_with {
        if !payload.ends_with(suffix) {
            return false;
        }
    }
    true
}

fn find_vanity_wallet_mnemonic_parallel(
    starts_with: Option<&str>,
    ends_with: Option<&str>,
    tries_limit: u64,
    mnemonic_pwd: &str,
    worker_count: usize,
) -> Result<Option<VanityMatch>, String> {
    let workers = worker_count.max(1);
    let stop = Arc::new(AtomicBool::new(false));
    let attempts_claimed = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<VanityMatch>();

    let starts_owned = starts_with.map(|s| s.to_string());
    let ends_owned = ends_with.map(|s| s.to_string());
    let mnemonic_pwd = Arc::new(mnemonic_pwd.to_string());
    let hkdf_salt = Arc::new(hkdf_salt_for_wallet_derivation());

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        let attempts_claimed = Arc::clone(&attempts_claimed);
        let starts_owned = starts_owned.clone();
        let ends_owned = ends_owned.clone();
        let mnemonic_pwd = Arc::clone(&mnemonic_pwd);
        let hkdf_salt = Arc::clone(&hkdf_salt);

        handles.push(thread::spawn(move || {
            let secp = Secp256k1::new();
            let mut rng = rand::rng();
            let mut chunk_next = 0u64;
            let mut chunk_end_exclusive = 0u64;
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                if chunk_next >= chunk_end_exclusive {
                    let claimed_start = attempts_claimed
                        .fetch_add(VANITY_ATTEMPT_RESERVATION_CHUNK, Ordering::Relaxed);
                    if claimed_start >= tries_limit {
                        break;
                    }
                    chunk_next = claimed_start;
                    chunk_end_exclusive = claimed_start
                        .saturating_add(VANITY_ATTEMPT_RESERVATION_CHUNK)
                        .min(tries_limit);
                }
                let attempt = chunk_next + 1;
                chunk_next += 1;

                let Ok(mnemonic) = generate_mnemonic_12_fast(&mut rng) else {
                    continue;
                };
                let Ok(derived) =
                    derive_secret_key_from_mnemonic_fast(&mnemonic, &mnemonic_pwd, &hkdf_salt)
                else {
                    continue;
                };
                let Ok(sk) = SecretKey::from_byte_array(derived) else {
                    continue;
                };

                let pk = PublicKey::from_secret_key(&secp, &sk);
                let public_key = pk.to_string();
                let address = pubkey_to_address(&public_key);

                if !address_matches_vanity(&address, starts_owned.as_deref(), ends_owned.as_deref())
                {
                    continue;
                }

                if stop
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    let _ = tx.send(VanityMatch {
                        sk,
                        mnemonic: Some(mnemonic.to_string()),
                        public_key,
                        address,
                        attempts: attempt,
                    });
                }
                break;
            }
        }));
    }
    drop(tx);

    let mut last_progress_printed = 0u64;
    let progress_started = Instant::now();
    let mut last_progress_instant = progress_started;
    let mut last_progress_attempts = 0u64;
    let mut found: Option<VanityMatch> = None;
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(result) => {
                found = Some(result);
                stop.store(true, Ordering::SeqCst);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let current = attempts_claimed.load(Ordering::Relaxed).min(tries_limit);
                if current >= last_progress_printed.saturating_add(10_000) {
                    let now = Instant::now();
                    let interval_attempts = current.saturating_sub(last_progress_attempts);
                    let interval_secs = now
                        .duration_since(last_progress_instant)
                        .as_secs_f64()
                        .max(f64::EPSILON);
                    let total_secs = now
                        .duration_since(progress_started)
                        .as_secs_f64()
                        .max(f64::EPSILON);
                    println!(
                        "Vanity search attempts: {} | rate={} | avg={} | elapsed={:.1}s",
                        current,
                        format_attempt_rate_per_sec(interval_attempts as f64 / interval_secs),
                        format_attempt_rate_per_sec(current as f64 / total_secs),
                        total_secs
                    );
                    last_progress_printed = current;
                    last_progress_instant = now;
                    last_progress_attempts = current;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    for handle in handles {
        let _ = handle.join();
    }

    Ok(found)
}

fn resolve_raw_vanity_candidate(
    counter: u64,
    base_seed: &[u8; 32],
    starts_with: Option<&str>,
    ends_with: Option<&str>,
    cpu_address_filter: RawFastFilter,
) -> Option<VanityMatch> {
    let sk_bytes = deterministic_raw_private_key(base_seed, counter);
    let sk = SecretKey::from_byte_array(sk_bytes).ok()?;
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let public_key = pk.to_string();
    let address_bytes = address_bytes_from_public_key(&public_key);
    if !raw_bytes_fast_filter_matches(&address_bytes, cpu_address_filter) {
        return None;
    }
    let payload = bs58::encode(address_bytes).into_string();
    let address = format!("LFS{}", payload);
    if !address_matches_vanity(&address, starts_with, ends_with) {
        return None;
    }
    Some(VanityMatch {
        sk,
        mnemonic: None,
        public_key,
        address,
        attempts: counter.saturating_add(1),
    })
}

fn find_vanity_wallet_raw_parallel(
    starts_with: Option<&str>,
    ends_with: Option<&str>,
    tries_limit: u64,
    base_seed: [u8; 32],
    cpu_address_filter: RawFastFilter,
    worker_count: usize,
) -> Result<Option<VanityMatch>, String> {
    let workers = worker_count.max(1);
    let stop = Arc::new(AtomicBool::new(false));
    let counters_claimed = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<VanityMatch>();

    let starts_owned = starts_with.map(|s| s.to_string());
    let ends_owned = ends_with.map(|s| s.to_string());
    let base_seed = Arc::new(base_seed);

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        let counters_claimed = Arc::clone(&counters_claimed);
        let starts_owned = starts_owned.clone();
        let ends_owned = ends_owned.clone();
        let base_seed = Arc::clone(&base_seed);

        handles.push(thread::spawn(move || {
            let mut chunk_next = 0u64;
            let mut chunk_end_exclusive = 0u64;
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                if chunk_next >= chunk_end_exclusive {
                    let claimed_start = counters_claimed
                        .fetch_add(VANITY_ATTEMPT_RESERVATION_CHUNK, Ordering::Relaxed);
                    if claimed_start >= tries_limit {
                        break;
                    }
                    chunk_next = claimed_start;
                    chunk_end_exclusive = claimed_start
                        .saturating_add(VANITY_ATTEMPT_RESERVATION_CHUNK)
                        .min(tries_limit);
                }

                let counter = chunk_next;
                chunk_next += 1;

                if let Some(found) = resolve_raw_vanity_candidate(
                    counter,
                    base_seed.as_ref(),
                    starts_owned.as_deref(),
                    ends_owned.as_deref(),
                    cpu_address_filter,
                ) {
                    if stop
                        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        let _ = tx.send(found);
                    }
                    break;
                }
            }
        }));
    }
    drop(tx);

    let mut last_progress_printed = 0u64;
    let progress_started = Instant::now();
    let mut last_progress_instant = progress_started;
    let mut last_progress_attempts = 0u64;
    let mut found: Option<VanityMatch> = None;
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(result) => {
                found = Some(result);
                stop.store(true, Ordering::SeqCst);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let current = counters_claimed.load(Ordering::Relaxed).min(tries_limit);
                if current >= last_progress_printed.saturating_add(50_000) {
                    let now = Instant::now();
                    let interval_attempts = current.saturating_sub(last_progress_attempts);
                    let interval_secs = now
                        .duration_since(last_progress_instant)
                        .as_secs_f64()
                        .max(f64::EPSILON);
                    let total_secs = now
                        .duration_since(progress_started)
                        .as_secs_f64()
                        .max(f64::EPSILON);
                    println!(
                        "RAW vanity attempts: {} | rate={} | avg={} | elapsed={:.1}s (cpu-workers={})",
                        current,
                        format_attempt_rate_per_sec(interval_attempts as f64 / interval_secs),
                        format_attempt_rate_per_sec(current as f64 / total_secs),
                        total_secs,
                        workers
                    );
                    last_progress_printed = current;
                    last_progress_instant = now;
                    last_progress_attempts = current;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    for handle in handles {
        let _ = handle.join();
    }

    Ok(found)
}

fn find_vanity_wallet_gpu_raw(
    starts_with: Option<&str>,
    ends_with: Option<&str>,
    tries_limit: u64,
    base_seed: [u8; 32],
    gpu_filter: RawFastFilter,
    cpu_address_filter: RawFastFilter,
    requested_workers: usize,
) -> Result<Option<VanityMatch>, String> {
    if tries_limit == 0 {
        return Ok(None);
    }

    let target_batch = requested_workers
        .clamp(1, 256)
        .saturating_mul(4096)
        .clamp(4096, 262_144);
    let max_hits = RAW_GPU_MAX_HITS_PER_BATCH.min(target_batch as u32).max(64);
    let runtime = GpuComputeRuntime::new(
        None,
        "GPU raw vanity runtime on",
        "wallet-cli-gpu-raw-vanity",
    )?;
    let mut session =
        GpuRawVanitySession::new_with_runtime(&runtime, target_batch as u32, max_hits)?;
    let mut checked = 0u64;
    let mut next_counter = 0u64;
    let progress_started = Instant::now();
    let mut last_progress_instant = progress_started;
    let mut last_progress_checked = 0u64;
    let mut batches = 0u64;

    println!(
        "GPU RAW vanity search enabled: batch_size={} max_hits={} gpu_filter_bits={} cpu_address_filter_bits={}",
        target_batch,
        session.max_hits(),
        gpu_filter.bits,
        cpu_address_filter.bits
    );

    while checked < tries_limit {
        let remaining = tries_limit - checked;
        let candidate_count = remaining.min(target_batch as u64) as u32;
        let scan_cfg = GpuRawVanityBatchConfig {
            base_seed,
            start_counter: next_counter,
            candidate_count,
            filter_bits: gpu_filter.bits,
            filter_value: gpu_filter.value,
            max_hits: session.max_hits().min(candidate_count),
            stop_after_hits: 0,
        };
        let scan = session.scan_batch(&scan_cfg)?;
        if scan.candidate_count != candidate_count {
            return Err(format!(
                "GPU raw vanity batch size mismatch (reported {} expected {})",
                scan.candidate_count, candidate_count
            ));
        }
        checked = checked.saturating_add(candidate_count as u64);
        next_counter = next_counter.saturating_add(candidate_count as u64);
        batches = batches.saturating_add(1);

        if scan.hit_count > scan.stored_hit_indices.len() as u64 {
            return Err(format!(
                "GPU raw vanity hit buffer saturated (hit_count={} stored={}). Increase filter bits or lower batch size.",
                scan.hit_count,
                scan.stored_hit_indices.len()
            ));
        }

        for hit_idx in scan.stored_hit_indices {
            let counter = scan_cfg.start_counter.saturating_add(hit_idx as u64);
            if let Some(found) = resolve_raw_vanity_candidate(
                counter,
                &base_seed,
                starts_with,
                ends_with,
                cpu_address_filter,
            ) {
                return Ok(Some(found));
            }
        }

        if checked.saturating_sub(last_progress_checked) >= 100_000 {
            let now = Instant::now();
            let delta = checked.saturating_sub(last_progress_checked);
            let interval_secs = now
                .duration_since(last_progress_instant)
                .as_secs_f64()
                .max(f64::EPSILON);
            let total_secs = now
                .duration_since(progress_started)
                .as_secs_f64()
                .max(f64::EPSILON);
            println!(
                "RAW vanity attempts: {} | rate={} | avg={} | elapsed={:.1}s (gpu, last_batch_attempts={}, last_batch_hits={}, stop_flag={}, batch_elapsed={:.4}s)",
                checked,
                format_attempt_rate_per_sec(delta as f64 / interval_secs),
                format_attempt_rate_per_sec(checked as f64 / total_secs),
                total_secs,
                scan.attempts,
                scan.hit_count,
                scan.stop_flag_triggered,
                scan.elapsed.as_secs_f64()
            );
            last_progress_instant = now;
            last_progress_checked = checked;
        }
    }

    let elapsed = progress_started.elapsed().as_secs_f64().max(f64::EPSILON);
    println!(
        "RAW vanity GPU scan exhausted after {} attempts across {} batches ({:.2} K/s).",
        checked,
        batches,
        (checked as f64 / elapsed) / 1_000.0
    );
    Ok(None)
}

fn find_vanity_wallet_gpu_hybrid(
    starts_with: Option<&str>,
    ends_with: Option<&str>,
    tries_limit: u64,
    mnemonic_pwd: &str,
    requested_workers: usize,
) -> Result<Option<VanityMatch>, String> {
    let secp = Secp256k1::new();
    let mut rng = rand::rng();
    let hkdf_salt = hkdf_salt_for_wallet_derivation();
    let mut attempts = 0u64;
    let mut last_progress_printed = 0u64;
    let progress_started = Instant::now();
    let mut last_progress_instant = progress_started;
    let mut last_progress_attempts = 0u64;
    let target_batch = requested_workers
        .clamp(1, 256)
        .saturating_mul(128)
        .clamp(64, 2048);
    let mut gpu_runtime: Option<GpuComputeRuntime> = None;
    let mut gpu_pubkey_hash_session: Option<GpuPubkeySha256Session> = None;
    let mut gpu_filter_session: Option<GpuPayloadBatchFilterSession> = None;

    println!(
        "GPU hybrid vanity search enabled (CPU secp256k1 -> GPU SHA256(pubkey) -> CPU base58 -> GPU filter), batch_size={}",
        target_batch
    );

    while attempts < tries_limit {
        let mut candidates = Vec::<GpuHybridCandidate>::with_capacity(target_batch);
        let mut pubkeys = Vec::<String>::with_capacity(target_batch);

        while candidates.len() < target_batch && attempts < tries_limit {
            attempts += 1;

            let Ok(mnemonic) = generate_mnemonic_12_fast(&mut rng) else {
                continue;
            };
            let Ok(derived) =
                derive_secret_key_from_mnemonic_fast(&mnemonic, mnemonic_pwd, &hkdf_salt)
            else {
                continue;
            };
            let Ok(sk) = SecretKey::from_byte_array(derived) else {
                continue;
            };

            let pk = PublicKey::from_secret_key(&secp, &sk);
            let public_key = pk.to_string();
            if !public_key.is_ascii() || public_key.len() != GPU_PUBKEY_SHA256_ASCII_LEN {
                continue;
            }
            pubkeys.push(public_key.clone());
            candidates.push(GpuHybridCandidate {
                sk,
                mnemonic,
                attempts,
            });
        }

        if candidates.is_empty() {
            continue;
        }

        if attempts >= last_progress_printed.saturating_add(10_000) {
            let now = Instant::now();
            let interval_attempts = attempts.saturating_sub(last_progress_attempts);
            let interval_secs = now
                .duration_since(last_progress_instant)
                .as_secs_f64()
                .max(f64::EPSILON);
            let total_secs = now
                .duration_since(progress_started)
                .as_secs_f64()
                .max(f64::EPSILON);
            println!(
                "Vanity search attempts: {} | rate={} | avg={} | elapsed={:.1}s (gpu-hybrid, current batch={})",
                attempts,
                format_attempt_rate_per_sec(interval_attempts as f64 / interval_secs),
                format_attempt_rate_per_sec(attempts as f64 / total_secs),
                total_secs,
                candidates.len()
            );
            last_progress_printed = attempts;
            last_progress_instant = now;
            last_progress_attempts = attempts;
        }

        let candidate_count = pubkeys.len() as u32;
        let needs_new_hash_session = gpu_pubkey_hash_session.as_ref().is_none_or(|session| {
            session.pubkey_len() != GPU_PUBKEY_SHA256_ASCII_LEN
                || session.max_candidates() < candidate_count
        });
        if needs_new_hash_session {
            if gpu_runtime.is_none() {
                gpu_runtime = Some(GpuComputeRuntime::new(
                    None,
                    "GPU vanity hybrid runtime on",
                    "wallet-cli-gpu-vanity-hybrid",
                )?);
            }
            let runtime = gpu_runtime
                .as_ref()
                .ok_or_else(|| "GPU runtime not initialized".to_string())?;
            gpu_pubkey_hash_session = Some(GpuPubkeySha256Session::new_with_runtime(
                runtime,
                GPU_PUBKEY_SHA256_ASCII_LEN,
                target_batch as u32,
            )?);
        }
        let hash_result = gpu_pubkey_hash_session
            .as_mut()
            .ok_or_else(|| "GPU pubkey SHA-256 session not initialized".to_string())?
            .hash_pubkeys(&pubkeys, false)?;

        let mut payloads = Vec::<String>::with_capacity(hash_result.digests.len());
        let mut candidate_index_map = Vec::<u32>::with_capacity(hash_result.digests.len());
        let mut expected_payload_len: Option<usize> = None;
        for (idx, digest) in hash_result.digests.iter().enumerate() {
            let payload = bs58::encode(&digest[..20]).into_string();
            if payload.is_empty() {
                continue;
            }
            match expected_payload_len {
                None => expected_payload_len = Some(payload.len()),
                Some(len) if payload.len() != len => continue,
                Some(_) => {}
            }
            candidate_index_map.push(idx as u32);
            payloads.push(payload);
        }
        if payloads.is_empty() {
            continue;
        }

        let filter_cfg = GpuPayloadBatchFilterConfig {
            prefix: starts_with.map(str::to_string),
            suffix: ends_with.map(str::to_string),
            max_hits: 8,
            stop_after_hits: 1,
        };

        let payload_len = payloads[0].len();
        let candidate_count = payloads.len() as u32;
        let needs_new_session = gpu_filter_session.as_ref().is_none_or(|session| {
            session.payload_len() != payload_len || session.max_candidates() < candidate_count
        });
        if needs_new_session {
            if gpu_runtime.is_none() {
                gpu_runtime = Some(GpuComputeRuntime::new(
                    None,
                    "GPU vanity hybrid runtime on",
                    "wallet-cli-gpu-vanity-hybrid",
                )?);
            }
            let runtime = gpu_runtime
                .as_ref()
                .ok_or_else(|| "GPU runtime not initialized".to_string())?;
            gpu_filter_session = Some(GpuPayloadBatchFilterSession::new_with_runtime(
                runtime,
                payload_len,
                target_batch as u32,
            )?);
        }
        let filter_result = gpu_filter_session
            .as_mut()
            .ok_or_else(|| "GPU filter session not initialized".to_string())?
            .filter_batch(&payloads, &filter_cfg)?;
        if let Some(first_idx) = filter_result.stored_hit_indices.first().copied() {
            let filtered_idx = first_idx as usize;
            let idx = *candidate_index_map.get(filtered_idx).ok_or_else(|| {
                format!(
                    "GPU returned out-of-range filtered candidate index {}",
                    filtered_idx
                )
            })? as usize;
            let candidate = candidates
                .into_iter()
                .nth(idx)
                .ok_or_else(|| format!("GPU returned out-of-range candidate index {}", idx))?;
            let payload = payloads.get(filtered_idx).ok_or_else(|| {
                format!(
                    "Missing payload for filtered candidate index {}",
                    filtered_idx
                )
            })?;
            let address = format!("LFS{}", payload);

            if !address_matches_vanity(&address, starts_with, ends_with) {
                return Err(format!(
                    "GPU hybrid verification failed for returned candidate index {}",
                    idx
                ));
            }

            return Ok(Some(VanityMatch {
                sk: candidate.sk,
                mnemonic: Some(candidate.mnemonic.to_string()),
                public_key: pubkeys
                    .get(idx)
                    .cloned()
                    .ok_or_else(|| format!("Missing pubkey for candidate index {}", idx))?,
                address,
                attempts: candidate.attempts,
            }));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{
        VanitySource, derive_secret_key_from_mnemonic_fast, hkdf_salt_for_wallet_derivation,
        parse_vanity_args, valid_vanity_pattern,
    };
    use bip39::{Language, Mnemonic};
    use blockchain_core::wallet_keystore::derive_secret_key_from_mnemonic;

    #[test]
    fn fast_derivation_matches_blockchain_core() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "lofswap-test";
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase).unwrap();
        let fast = derive_secret_key_from_mnemonic_fast(
            &mnemonic,
            passphrase,
            &hkdf_salt_for_wallet_derivation(),
        )
        .unwrap();
        let core = derive_secret_key_from_mnemonic(
            phrase,
            passphrase,
            blockchain_core::wallet_keystore::DEFAULT_DERIVATION_PATH,
        )
        .unwrap();
        assert_eq!(fast, core);
    }

    #[test]
    fn vanity_pattern_validation_stays_base58_only() {
        assert!(valid_vanity_pattern("abc123"));
        assert!(!valid_vanity_pattern("0OIl"));
        assert!(!valid_vanity_pattern("ab-c"));
    }

    #[test]
    fn parse_vanity_args_defaults_gpu_to_raw_source() {
        let parsed = parse_vanity_args(&["gpu"]).unwrap();
        assert_eq!(parsed.vanity_source, VanitySource::Raw);
    }

    #[test]
    fn parse_vanity_args_accepts_vanity_source_equals_form() {
        let parsed = parse_vanity_args(&["--vanity-source=mnemonic", "gpu"]).unwrap();
        assert_eq!(parsed.vanity_source, VanitySource::Mnemonic);
    }
}
