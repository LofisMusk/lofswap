use std::borrow::Cow;
use std::future::Future;
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use wgpu::{AdapterInfo as WgpuAdapterInfo, Backend as WgpuBackend, DeviceType as WgpuDeviceType};

#[derive(Debug, Clone)]
pub(crate) struct GpuAdapterSummary {
    pub(crate) name: String,
    pub(crate) backend: WgpuBackend,
    pub(crate) device_type: WgpuDeviceType,
    pub(crate) vendor: u32,
    pub(crate) vendor_name: &'static str,
    pub(crate) driver: String,
}

fn gpu_vendor_name(vendor: u32) -> &'static str {
    match vendor {
        0x10DE => "NVIDIA",
        0x8086 => "Intel",
        0x1002 | 0x1022 => "AMD",
        0x106B => "Apple",
        0 => "Unknown",
        _ => "Other",
    }
}

fn backend_preference_score(backend: WgpuBackend) -> i32 {
    #[cfg(target_os = "macos")]
    {
        return match backend {
            WgpuBackend::Metal => 100,
            WgpuBackend::Vulkan => 80,
            WgpuBackend::Dx12 => 20,
            WgpuBackend::Gl => 10,
            _ => 0,
        };
    }

    #[cfg(target_os = "windows")]
    {
        return match backend {
            WgpuBackend::Dx12 => 100,
            WgpuBackend::Vulkan => 90,
            WgpuBackend::Gl => 20,
            _ => 0,
        };
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        match backend {
            WgpuBackend::Vulkan => 100,
            WgpuBackend::Gl => 30,
            WgpuBackend::Metal => 10,
            WgpuBackend::Dx12 => 10,
            _ => 0,
        }
    }
}

fn device_type_score(device_type: WgpuDeviceType) -> i32 {
    match device_type {
        WgpuDeviceType::DiscreteGpu => 500,
        WgpuDeviceType::IntegratedGpu => 400,
        WgpuDeviceType::VirtualGpu => 200,
        WgpuDeviceType::Other => 100,
        WgpuDeviceType::Cpu => 0,
    }
}

fn summarize_adapter(info: WgpuAdapterInfo) -> GpuAdapterSummary {
    GpuAdapterSummary {
        name: info.name,
        backend: info.backend,
        device_type: info.device_type,
        vendor: info.vendor,
        vendor_name: gpu_vendor_name(info.vendor),
        driver: if info.driver.is_empty() {
            info.driver_info
        } else if info.driver_info.is_empty() {
            info.driver
        } else {
            format!("{} ({})", info.driver, info.driver_info)
        },
    }
}

pub(crate) fn list_gpu_adapters() -> Vec<GpuAdapterSummary> {
    let instance = wgpu::Instance::default();
    let adapters = instance.enumerate_adapters(wgpu::Backends::all());

    adapters
        .into_iter()
        .map(|adapter| summarize_adapter(adapter.get_info()))
        .collect()
}

pub(crate) fn select_best_gpu_adapter(adapters: &[GpuAdapterSummary]) -> Option<GpuAdapterSummary> {
    select_best_gpu_adapter_index(adapters).map(|idx| adapters[idx].clone())
}

fn select_best_gpu_adapter_index(adapters: &[GpuAdapterSummary]) -> Option<usize> {
    let has_non_cpu_gpu = adapters
        .iter()
        .any(|a| a.device_type != WgpuDeviceType::Cpu);

    adapters
        .iter()
        .enumerate()
        .filter(|(_, a)| !has_non_cpu_gpu || a.device_type != WgpuDeviceType::Cpu)
        .max_by_key(|(_, a)| device_type_score(a.device_type) + backend_preference_score(a.backend))
        .map(|(idx, _)| idx)
}

pub(crate) fn print_gpu_info() {
    let adapters = list_gpu_adapters();
    if adapters.is_empty() {
        println!("No adapters detected by wgpu.");
        return;
    }
    let best_idx = select_best_gpu_adapter_index(&adapters);
    println!("Detected {} adapter(s):", adapters.len());
    for (idx, adapter) in adapters.iter().enumerate() {
        let marker = if Some(idx) == best_idx { "*" } else { " " };
        println!(
            "{} [{}] {} | vendor={} (0x{:04x}) | type={:?} | backend={:?}",
            marker,
            idx,
            adapter.name,
            adapter.vendor_name,
            adapter.vendor,
            adapter.device_type,
            adapter.backend
        );
        if !adapter.driver.is_empty() {
            println!("    driver: {}", adapter.driver);
        }
    }
    if let Some(best) = best_idx.and_then(|idx| adapters.get(idx)) {
        println!(
            "Selected by ranking: [{}] {} ({:?}, {:?})",
            best_idx.unwrap_or(0),
            best.name,
            best.device_type,
            best.backend
        );
    }
}

fn simple_block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let waker: &Waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::sleep(Duration::from_millis(1)),
        }
    }
}

fn parse_u32_vec_le(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

fn select_adapter_for_run(
    requested_index: Option<usize>,
) -> Result<(usize, GpuAdapterSummary, wgpu::Adapter), String> {
    let instance = wgpu::Instance::default();
    let adapters = instance.enumerate_adapters(wgpu::Backends::all());
    if adapters.is_empty() {
        return Err("No adapters detected by wgpu".to_string());
    }

    let summaries: Vec<GpuAdapterSummary> = adapters
        .iter()
        .map(|adapter| summarize_adapter(adapter.get_info()))
        .collect();

    let selected_idx = if let Some(idx) = requested_index {
        if idx >= adapters.len() {
            return Err(format!(
                "Adapter index {} out of range (detected {})",
                idx,
                adapters.len()
            ));
        }
        idx
    } else {
        select_best_gpu_adapter_index(&summaries)
            .ok_or_else(|| "No suitable adapter selected".to_string())?
    };

    let adapter = instance
        .enumerate_adapters(wgpu::Backends::all())
        .into_iter()
        .nth(selected_idx)
        .ok_or_else(|| format!("Failed to reopen adapter index {}", selected_idx))?;

    Ok((selected_idx, summaries[selected_idx].clone(), adapter))
}

fn request_compute_device(
    adapter: &wgpu::Adapter,
    label: &'static str,
) -> Result<(wgpu::Device, wgpu::Queue), String> {
    simple_block_on(adapter.request_device(
        &wgpu::DeviceDescriptor {
            label: Some(label),
            required_features: wgpu::Features::empty(),
            required_limits: wgpu::Limits::downlevel_defaults(),
        },
        None,
    ))
    .map_err(|e| format!("request_device failed: {}", e))
}

#[derive(Clone)]
pub(crate) struct GpuComputeRuntime {
    device: Arc<wgpu::Device>,
    queue: Arc<wgpu::Queue>,
}

impl GpuComputeRuntime {
    pub(crate) fn new(
        requested_index: Option<usize>,
        banner_prefix: &str,
        device_label: &'static str,
    ) -> Result<Self, String> {
        let (selected_idx, summary, adapter) = select_adapter_for_run(requested_index)?;
        print_adapter_banner(banner_prefix, selected_idx, &summary);
        let (device, queue) = request_compute_device(&adapter, device_label)?;
        Ok(Self {
            device: Arc::new(device),
            queue: Arc::new(queue),
        })
    }
}

fn print_adapter_banner(prefix: &str, index: usize, summary: &GpuAdapterSummary) {
    println!(
        "{} [{}] {} | vendor={} (0x{:04x}) | type={:?} | backend={:?}",
        prefix,
        index,
        summary.name,
        summary.vendor_name,
        summary.vendor,
        summary.device_type,
        summary.backend
    );
    if !summary.driver.is_empty() {
        println!("Driver: {}", summary.driver);
    }
}

pub(crate) fn gpu_smoke_test(requested_index: Option<usize>) -> Result<(), String> {
    let (selected_idx, summary, adapter) = select_adapter_for_run(requested_index)?;
    print_adapter_banner("GPU smoke test on", selected_idx, &summary);

    let (device, queue) = request_compute_device(&adapter, "wallet-cli-gpu-smoke")?;

    let shader_src = r#"
@group(0) @binding(0)
var<storage, read_write> out_buf: array<u32>;

@compute @workgroup_size(1)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i: u32 = gid.x;
    if (i < 4u) {
        out_buf[i] = (i + 1u) * 7u;
    }
}
"#;

    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("wallet-cli-gpu-smoke-shader"),
        source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(shader_src)),
    });

    let storage_size = (4 * std::mem::size_of::<u32>()) as u64;
    let storage = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-smoke-storage"),
        size: storage_size,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });
    let readback = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-smoke-readback"),
        size: storage_size,
        usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
        mapped_at_creation: false,
    });

    let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("wallet-cli-gpu-smoke-bgl"),
        entries: &[wgpu::BindGroupLayoutEntry {
            binding: 0,
            visibility: wgpu::ShaderStages::COMPUTE,
            ty: wgpu::BindingType::Buffer {
                ty: wgpu::BufferBindingType::Storage { read_only: false },
                has_dynamic_offset: false,
                min_binding_size: None,
            },
            count: None,
        }],
    });

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("wallet-cli-gpu-smoke-pipeline-layout"),
        bind_group_layouts: &[&bind_group_layout],
        push_constant_ranges: &[],
    });

    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("wallet-cli-gpu-smoke-pipeline"),
        layout: Some(&pipeline_layout),
        module: &shader,
        entry_point: "main",
    });

    let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("wallet-cli-gpu-smoke-bg"),
        layout: &bind_group_layout,
        entries: &[wgpu::BindGroupEntry {
            binding: 0,
            resource: storage.as_entire_binding(),
        }],
    });

    let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
        label: Some("wallet-cli-gpu-smoke-encoder"),
    });
    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("wallet-cli-gpu-smoke-pass"),
            timestamp_writes: None,
        });
        pass.set_pipeline(&pipeline);
        pass.set_bind_group(0, &bind_group, &[]);
        pass.dispatch_workgroups(4, 1, 1);
    }
    encoder.copy_buffer_to_buffer(&storage, 0, &readback, 0, storage_size);
    queue.submit(Some(encoder.finish()));

    let (tx, rx) = mpsc::channel();
    readback
        .slice(..)
        .map_async(wgpu::MapMode::Read, move |res| {
            let _ = tx.send(res);
        });
    let _ = device.poll(wgpu::Maintain::Wait);

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("readback map failed: {}", e)),
        Err(_) => return Err("Timed out waiting for GPU readback".to_string()),
    }

    let mapped = readback.slice(..).get_mapped_range();
    let values = parse_u32_vec_le(&mapped);
    drop(mapped);
    readback.unmap();

    let expected = vec![7, 14, 21, 28];
    if values != expected {
        return Err(format!(
            "Unexpected GPU result: got {:?}, expected {:?}",
            values, expected
        ));
    }

    println!("GPU smoke test passed. Result buffer = {:?}", values);
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GpuPipelineProbeConfig {
    pub(crate) chunks: u32,
    pub(crate) workgroups_per_chunk: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GpuPipelineProbeResult {
    pub(crate) chunks_executed: u32,
    pub(crate) workgroups_per_chunk: u32,
    pub(crate) workgroup_size: u32,
    pub(crate) total_invocations: u64,
    pub(crate) elapsed: Duration,
}

const COUNTER_PIPELINE_WORKGROUP_SIZE: u32 = 64;

pub(crate) fn gpu_pipeline_test(
    requested_index: Option<usize>,
    config: GpuPipelineProbeConfig,
) -> Result<GpuPipelineProbeResult, String> {
    if config.chunks == 0 {
        return Err("chunks must be > 0".to_string());
    }
    if config.workgroups_per_chunk == 0 {
        return Err("workgroups_per_chunk must be > 0".to_string());
    }

    let total_invocations = config.chunks as u64
        * config.workgroups_per_chunk as u64
        * COUNTER_PIPELINE_WORKGROUP_SIZE as u64;
    if total_invocations > u32::MAX as u64 {
        return Err(format!(
            "Requested total invocations {} exceeds u32 counter capacity",
            total_invocations
        ));
    }

    let (selected_idx, summary, adapter) = select_adapter_for_run(requested_index)?;
    print_adapter_banner("GPU pipeline test on", selected_idx, &summary);

    let (device, queue) = request_compute_device(&adapter, "wallet-cli-gpu-pipeline-test")?;

    let shader_src = r#"
struct Counter {
    value: atomic<u32>,
}

@group(0) @binding(0)
var<storage, read_write> counter: Counter;

@compute @workgroup_size(64)
fn main() {
    atomicAdd(&counter.value, 1u);
}
"#;

    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("wallet-cli-gpu-counter-shader"),
        source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(shader_src)),
    });

    let counter_size = std::mem::size_of::<u32>() as u64;
    let counter_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-counter-storage"),
        size: counter_size,
        usage: wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let readback = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-counter-readback"),
        size: counter_size,
        usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
        mapped_at_creation: false,
    });
    queue.write_buffer(&counter_buffer, 0, &0u32.to_le_bytes());

    let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("wallet-cli-gpu-counter-bgl"),
        entries: &[wgpu::BindGroupLayoutEntry {
            binding: 0,
            visibility: wgpu::ShaderStages::COMPUTE,
            ty: wgpu::BindingType::Buffer {
                ty: wgpu::BufferBindingType::Storage { read_only: false },
                has_dynamic_offset: false,
                min_binding_size: None,
            },
            count: None,
        }],
    });
    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("wallet-cli-gpu-counter-pipeline-layout"),
        bind_group_layouts: &[&bind_group_layout],
        push_constant_ranges: &[],
    });
    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("wallet-cli-gpu-counter-pipeline"),
        layout: Some(&pipeline_layout),
        module: &shader,
        entry_point: "main",
    });
    let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("wallet-cli-gpu-counter-bind-group"),
        layout: &bind_group_layout,
        entries: &[wgpu::BindGroupEntry {
            binding: 0,
            resource: counter_buffer.as_entire_binding(),
        }],
    });

    let start = Instant::now();
    for chunk_idx in 0..config.chunks {
        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("wallet-cli-gpu-counter-encoder"),
        });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("wallet-cli-gpu-counter-pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(config.workgroups_per_chunk, 1, 1);
        }
        queue.submit(Some(encoder.finish()));

        if config.chunks <= 8 || chunk_idx + 1 == config.chunks {
            let done = chunk_idx + 1;
            println!(
                "GPU pipeline chunk {done}/{} submitted ({} workgroups/chunk)",
                config.chunks, config.workgroups_per_chunk
            );
        }
    }

    let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
        label: Some("wallet-cli-gpu-counter-readback-encoder"),
    });
    encoder.copy_buffer_to_buffer(&counter_buffer, 0, &readback, 0, counter_size);
    queue.submit(Some(encoder.finish()));

    let (tx, rx) = mpsc::channel();
    readback
        .slice(..)
        .map_async(wgpu::MapMode::Read, move |res| {
            let _ = tx.send(res);
        });
    let _ = device.poll(wgpu::Maintain::Wait);

    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("readback map failed: {}", e)),
        Err(_) => return Err("Timed out waiting for pipeline readback".to_string()),
    }

    let mapped = readback.slice(..).get_mapped_range();
    let values = parse_u32_vec_le(&mapped);
    drop(mapped);
    readback.unmap();

    let elapsed = start.elapsed();
    let observed = values.first().copied().unwrap_or_default() as u64;
    if observed != total_invocations {
        return Err(format!(
            "GPU pipeline counter mismatch: got {}, expected {}",
            observed, total_invocations
        ));
    }

    println!(
        "GPU pipeline test passed. total_invocations={} in {:.3}s ({:.2} Mops/s)",
        total_invocations,
        elapsed.as_secs_f64(),
        (total_invocations as f64 / elapsed.as_secs_f64().max(1e-9)) / 1_000_000.0
    );

    Ok(GpuPipelineProbeResult {
        chunks_executed: config.chunks,
        workgroups_per_chunk: config.workgroups_per_chunk,
        workgroup_size: COUNTER_PIPELINE_WORKGROUP_SIZE,
        total_invocations,
        elapsed,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct GpuVanityProbeConfig {
    pub(crate) chunks: u32,
    pub(crate) workgroups_per_chunk: u32,
    pub(crate) prefix: Option<String>,
    pub(crate) suffix: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GpuVanityProbeResult {
    pub(crate) total_candidates: u64,
    pub(crate) prefix_hits: u64,
    pub(crate) suffix_hits: u64,
    pub(crate) combined_hits: u64,
    pub(crate) first_hit_index: Option<u64>,
    pub(crate) elapsed: Duration,
}

const VANITY_PROBE_WORKGROUP_SIZE: u32 = 64;
const VANITY_PROBE_MAX_PATTERN_LEN: usize = 16;
const VANITY_PROBE_PAYLOAD_LEN: u32 = 20;
const VANITY_JOB_WORKGROUP_SIZE: u32 = 64;
const VANITY_JOB_MAX_PATTERN_LEN: usize = 16;
const VANITY_JOB_PAYLOAD_LEN: u32 = 20;
const VANITY_JOB_MAX_HITS: usize = 64;
const BASE58_ALPHABET_BYTES: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const GPU_FILTER_BATCH_MAX_PAYLOAD_LEN: usize = 64;
pub(crate) const GPU_PUBKEY_SHA256_ASCII_LEN: usize = 66;
const GPU_PUBKEY_SHA256_WORKGROUP_SIZE: u32 = 64;

fn sha256_ascii_host(input: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[derive(Debug)]
pub(crate) struct GpuPubkeySha256BatchResult {
    pub(crate) candidate_count: u32,
    pub(crate) digests: Vec<[u8; 32]>,
    pub(crate) verification_performed: bool,
    pub(crate) verified_digests: u64,
    pub(crate) verification_mismatches: u64,
    pub(crate) elapsed: Duration,
}

pub(crate) struct GpuPubkeySha256Session {
    pubkey_len: usize,
    max_candidates: u32,
    device: Arc<wgpu::Device>,
    queue: Arc<wgpu::Queue>,
    params_buffer: wgpu::Buffer,
    pubkey_bytes_buffer: wgpu::Buffer,
    digests_words_buffer: wgpu::Buffer,
    digests_words_readback: wgpu::Buffer,
    pipeline: wgpu::ComputePipeline,
    bind_group: wgpu::BindGroup,
}

impl GpuPubkeySha256Session {
    pub(crate) fn new(
        requested_index: Option<usize>,
        pubkey_len: usize,
        max_candidates: u32,
    ) -> Result<Self, String> {
        let runtime = GpuComputeRuntime::new(
            requested_index,
            "GPU pubkey SHA-256 session on",
            "wallet-cli-gpu-pubkey-sha256",
        )?;
        Self::new_with_runtime(&runtime, pubkey_len, max_candidates)
    }

    pub(crate) fn new_with_runtime(
        runtime: &GpuComputeRuntime,
        pubkey_len: usize,
        max_candidates: u32,
    ) -> Result<Self, String> {
        if pubkey_len != GPU_PUBKEY_SHA256_ASCII_LEN {
            return Err(format!(
                "GPU pubkey SHA-256 currently supports only {}-byte compressed pubkey hex strings (got {})",
                GPU_PUBKEY_SHA256_ASCII_LEN, pubkey_len
            ));
        }
        if max_candidates == 0 {
            return Err("max_candidates must be > 0".to_string());
        }

        let device = Arc::clone(&runtime.device);
        let queue = Arc::clone(&runtime.queue);

        let shader_src = r#"
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

const SHA256_K: array<u32, 64> = array<u32, 64>(
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

fn sha256_compress(state_in: array<u32, 8>, w_in: array<u32, 64>) -> array<u32, 8> {
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
        if (t >= 64u) { break; }
        let t1 = h + big_sigma1(e) + ch(e, f, g) + SHA256_K[t] + w_in[t];
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

@group(0) @binding(0)
var<storage, read> params: array<u32>; // [candidate_count]
@group(0) @binding(1)
var<storage, read> pubkey_ascii_bytes: array<u32>;
@group(0) @binding(2)
var<storage, read_write> digest_words_out: array<u32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let candidate_count = params[0];
    let idx = gid.x;
    if (idx >= candidate_count) {
        return;
    }

    let msg_base = idx * 66u;
    let out_base = idx * 8u;

    var state = array<u32, 8>(
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    );

    var w0: array<u32, 64>;
    var t = 0u;
    loop {
        if (t >= 16u) { break; }
        let off = msg_base + t * 4u;
        let b0 = pubkey_ascii_bytes[off + 0u] & 0xffu;
        let b1 = pubkey_ascii_bytes[off + 1u] & 0xffu;
        let b2 = pubkey_ascii_bytes[off + 2u] & 0xffu;
        let b3 = pubkey_ascii_bytes[off + 3u] & 0xffu;
        w0[t] = (b0 << 24u) | (b1 << 16u) | (b2 << 8u) | b3;
        t = t + 1u;
    }
    t = 16u;
    loop {
        if (t >= 64u) { break; }
        w0[t] = small_sigma1(w0[t - 2u]) + w0[t - 7u] + small_sigma0(w0[t - 15u]) + w0[t - 16u];
        t = t + 1u;
    }
    state = sha256_compress(state, w0);

    var w1: array<u32, 64>;
    t = 0u;
    loop {
        if (t >= 64u) { break; }
        w1[t] = 0u;
        t = t + 1u;
    }
    let m64 = pubkey_ascii_bytes[msg_base + 64u] & 0xffu;
    let m65 = pubkey_ascii_bytes[msg_base + 65u] & 0xffu;
    w1[0] = (m64 << 24u) | (m65 << 16u) | (0x80u << 8u);
    w1[14] = 0u;
    w1[15] = 528u;
    t = 16u;
    loop {
        if (t >= 64u) { break; }
        w1[t] = small_sigma1(w1[t - 2u]) + w1[t - 7u] + small_sigma0(w1[t - 15u]) + w1[t - 16u];
        t = t + 1u;
    }
    state = sha256_compress(state, w1);

    var i = 0u;
    loop {
        if (i >= 8u) { break; }
        digest_words_out[out_base + i] = state[i];
        i = i + 1u;
    }
}
"#;

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("wallet-cli-gpu-pubkey-sha256-shader"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(shader_src)),
        });

        let params_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-pubkey-sha256-params"),
            size: std::mem::size_of::<u32>() as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let pubkey_bytes_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-pubkey-sha256-input"),
            size: (max_candidates as u64 * pubkey_len as u64 * std::mem::size_of::<u32>() as u64),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let digests_words_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-pubkey-sha256-output"),
            size: (max_candidates as u64 * 8 * std::mem::size_of::<u32>() as u64),
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let digests_words_readback = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-pubkey-sha256-readback"),
            size: (max_candidates as u64 * 8 * std::mem::size_of::<u32>() as u64),
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("wallet-cli-gpu-pubkey-sha256-bgl"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("wallet-cli-gpu-pubkey-sha256-pipeline-layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("wallet-cli-gpu-pubkey-sha256-pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: "main",
        });
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("wallet-cli-gpu-pubkey-sha256-bind-group"),
            layout: &bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: params_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: pubkey_bytes_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: digests_words_buffer.as_entire_binding(),
                },
            ],
        });

        Ok(Self {
            pubkey_len,
            max_candidates,
            device,
            queue,
            params_buffer,
            pubkey_bytes_buffer,
            digests_words_buffer,
            digests_words_readback,
            pipeline,
            bind_group,
        })
    }

    pub(crate) fn pubkey_len(&self) -> usize {
        self.pubkey_len
    }

    pub(crate) fn max_candidates(&self) -> u32 {
        self.max_candidates
    }

    pub(crate) fn hash_pubkeys(
        &mut self,
        pubkeys: &[String],
        verify_with_cpu: bool,
    ) -> Result<GpuPubkeySha256BatchResult, String> {
        if pubkeys.is_empty() {
            return Err("pubkey batch is empty".to_string());
        }
        if pubkeys.len() > self.max_candidates as usize {
            return Err(format!(
                "pubkey batch too large for session ({} > {})",
                pubkeys.len(),
                self.max_candidates
            ));
        }
        if pubkeys.iter().any(|pk| !pk.is_ascii()) {
            return Err("all pubkeys must be ASCII".to_string());
        }
        if pubkeys.iter().any(|pk| pk.len() != self.pubkey_len) {
            return Err(format!(
                "all pubkeys must have fixed length {}",
                self.pubkey_len
            ));
        }
        if self.pubkey_len != GPU_PUBKEY_SHA256_ASCII_LEN {
            return Err(format!(
                "GPU pubkey SHA-256 expects pubkey length {}",
                GPU_PUBKEY_SHA256_ASCII_LEN
            ));
        }

        let candidate_count = pubkeys.len() as u32;
        let mut input_words = Vec::with_capacity(pubkeys.len() * self.pubkey_len);
        for pk in pubkeys {
            for b in pk.as_bytes() {
                input_words.push(*b as u32);
            }
        }

        self.queue
            .write_buffer(&self.params_buffer, 0, &candidate_count.to_le_bytes());
        self.queue.write_buffer(
            &self.pubkey_bytes_buffer,
            0,
            &u32_slice_to_le_bytes(&input_words),
        );
        self.queue.write_buffer(
            &self.digests_words_buffer,
            0,
            &u32_slice_to_le_bytes(&vec![0u32; pubkeys.len() * 8]),
        );

        let dispatch_workgroups = candidate_count.div_ceil(GPU_PUBKEY_SHA256_WORKGROUP_SIZE);
        let start = Instant::now();
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wallet-cli-gpu-pubkey-sha256-encoder"),
            });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("wallet-cli-gpu-pubkey-sha256-pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &self.bind_group, &[]);
            pass.dispatch_workgroups(dispatch_workgroups, 1, 1);
        }
        self.queue.submit(Some(encoder.finish()));
        let _ = self.device.poll(wgpu::Maintain::Poll);

        let copy_size = (pubkeys.len() * 8 * std::mem::size_of::<u32>()) as u64;
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wallet-cli-gpu-pubkey-sha256-readback-encoder"),
            });
        encoder.copy_buffer_to_buffer(
            &self.digests_words_buffer,
            0,
            &self.digests_words_readback,
            0,
            copy_size,
        );
        self.queue.submit(Some(encoder.finish()));

        let (tx, rx) = mpsc::channel();
        self.digests_words_readback
            .slice(..copy_size)
            .map_async(wgpu::MapMode::Read, move |res| {
                let _ = tx.send(res);
            });
        let _ = self.device.poll(wgpu::Maintain::Wait);
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("GPU pubkey SHA-256 readback map failed: {}", e)),
            Err(_) => return Err("Timed out waiting for GPU pubkey SHA-256 readback".to_string()),
        }

        let digest_words = {
            let mapped = self
                .digests_words_readback
                .slice(..copy_size)
                .get_mapped_range();
            let words = parse_u32_vec_le(&mapped);
            drop(mapped);
            self.digests_words_readback.unmap();
            words
        };
        if digest_words.len() != pubkeys.len() * 8 {
            return Err(format!(
                "Unexpected GPU pubkey SHA-256 output size: {} words (expected {})",
                digest_words.len(),
                pubkeys.len() * 8
            ));
        }

        let mut digests = Vec::with_capacity(pubkeys.len());
        for chunk in digest_words.chunks_exact(8) {
            let mut digest = [0u8; 32];
            for (i, word) in chunk.iter().enumerate() {
                let start = i * 4;
                digest[start..start + 4].copy_from_slice(&word.to_be_bytes());
            }
            digests.push(digest);
        }

        let mut verified_digests = 0u64;
        let mut verification_mismatches = 0u64;
        if verify_with_cpu {
            for (pk, digest) in pubkeys.iter().zip(digests.iter()) {
                let expected = sha256_ascii_host(pk);
                if expected == *digest {
                    verified_digests += 1;
                } else {
                    verification_mismatches += 1;
                }
            }
            if verification_mismatches > 0 {
                return Err(format!(
                    "GPU pubkey SHA-256 verification mismatch: {} of {} digests failed CPU verification",
                    verification_mismatches,
                    pubkeys.len()
                ));
            }
        }

        Ok(GpuPubkeySha256BatchResult {
            candidate_count,
            digests,
            verification_performed: verify_with_cpu,
            verified_digests,
            verification_mismatches,
            elapsed: start.elapsed(),
        })
    }
}

pub(crate) fn gpu_hash_pubkey_batch(
    requested_index: Option<usize>,
    pubkeys: &[String],
    verify_with_cpu: bool,
) -> Result<GpuPubkeySha256BatchResult, String> {
    let Some(first) = pubkeys.first() else {
        return Err("pubkey batch is empty".to_string());
    };
    let mut session =
        GpuPubkeySha256Session::new(requested_index, first.len(), pubkeys.len() as u32)?;
    session.hash_pubkeys(pubkeys, verify_with_cpu)
}

fn u32_slice_to_le_bytes(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn parse_vanity_probe_pattern(label: &str, pattern: Option<&str>) -> Result<Vec<u32>, String> {
    let Some(pattern) = pattern else {
        return Ok(vec![0; VANITY_PROBE_MAX_PATTERN_LEN]);
    };
    let bytes = pattern.as_bytes();
    if bytes.len() > VANITY_PROBE_MAX_PATTERN_LEN {
        return Err(format!(
            "{} too long for GPU vanity probe (max {} chars for now)",
            label, VANITY_PROBE_MAX_PATTERN_LEN
        ));
    }
    if !bytes.is_ascii() {
        return Err(format!("{} must be ASCII for GPU vanity probe", label));
    }
    let mut out = vec![0u32; VANITY_PROBE_MAX_PATTERN_LEN];
    for (idx, b) in bytes.iter().enumerate() {
        out[idx] = *b as u32;
    }
    Ok(out)
}

fn pseudo_payload_char_host(candidate_index: u32, pos: u32) -> u8 {
    let mut x = candidate_index ^ pos.wrapping_mul(2_654_435_761);
    x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    x ^= x >> 16;
    BASE58_ALPHABET_BYTES[(x % 58) as usize]
}

fn pseudo_payload_matches_host(
    candidate_index: u32,
    prefix: Option<&str>,
    suffix: Option<&str>,
) -> bool {
    if let Some(prefix) = prefix {
        for (pos, b) in prefix.as_bytes().iter().enumerate() {
            if pseudo_payload_char_host(candidate_index, pos as u32) != *b {
                return false;
            }
        }
    }
    if let Some(suffix) = suffix {
        let suffix_len = suffix.len() as u32;
        for (offset, b) in suffix.as_bytes().iter().enumerate() {
            let pos = VANITY_JOB_PAYLOAD_LEN - suffix_len + offset as u32;
            if pseudo_payload_char_host(candidate_index, pos) != *b {
                return false;
            }
        }
    }
    true
}

fn payload_matches_filters_host(payload: &str, prefix: Option<&str>, suffix: Option<&str>) -> bool {
    if let Some(prefix) = prefix {
        if !payload.starts_with(prefix) {
            return false;
        }
    }
    if let Some(suffix) = suffix {
        if !payload.ends_with(suffix) {
            return false;
        }
    }
    true
}

fn build_pseudo_payload_chunk_words(
    start_index: u32,
    candidate_count: u32,
    payload_len: u32,
) -> Vec<u32> {
    let mut words = Vec::with_capacity(candidate_count as usize * payload_len as usize);
    for offset in 0..candidate_count {
        let candidate_index = start_index.wrapping_add(offset);
        for pos in 0..payload_len {
            words.push(pseudo_payload_char_host(candidate_index, pos) as u32);
        }
    }
    words
}

pub(crate) fn gpu_vanity_probe(
    requested_index: Option<usize>,
    config: &GpuVanityProbeConfig,
) -> Result<GpuVanityProbeResult, String> {
    if config.chunks == 0 {
        return Err("chunks must be > 0".to_string());
    }
    if config.workgroups_per_chunk == 0 {
        return Err("workgroups_per_chunk must be > 0".to_string());
    }

    let prefix_len = config.prefix.as_ref().map(|s| s.len()).unwrap_or(0);
    let suffix_len = config.suffix.as_ref().map(|s| s.len()).unwrap_or(0);
    if prefix_len > VANITY_PROBE_MAX_PATTERN_LEN {
        return Err(format!(
            "prefix too long for probe (max {})",
            VANITY_PROBE_MAX_PATTERN_LEN
        ));
    }
    if suffix_len > VANITY_PROBE_MAX_PATTERN_LEN {
        return Err(format!(
            "suffix too long for probe (max {})",
            VANITY_PROBE_MAX_PATTERN_LEN
        ));
    }
    if (prefix_len + suffix_len) as u32 > VANITY_PROBE_PAYLOAD_LEN {
        return Err(format!(
            "prefix+suffix too long for probe payload (max {} total chars)",
            VANITY_PROBE_PAYLOAD_LEN
        ));
    }

    let invocations_per_chunk =
        config.workgroups_per_chunk as u64 * VANITY_PROBE_WORKGROUP_SIZE as u64;
    let total_candidates = config.chunks as u64 * invocations_per_chunk;
    if total_candidates > u32::MAX as u64 {
        return Err(format!(
            "Requested total candidates {} exceeds current u32 probe limit",
            total_candidates
        ));
    }

    let prefix_words = parse_vanity_probe_pattern("prefix", config.prefix.as_deref())?;
    let suffix_words = parse_vanity_probe_pattern("suffix", config.suffix.as_deref())?;

    let (selected_idx, summary, adapter) = select_adapter_for_run(requested_index)?;
    print_adapter_banner("GPU vanity probe on", selected_idx, &summary);

    let (device, queue) = request_compute_device(&adapter, "wallet-cli-gpu-vanity-probe")?;

    let shader_src = r#"
struct ProbeResults {
    attempts: atomic<u32>,
    prefix_hits: atomic<u32>,
    suffix_hits: atomic<u32>,
    combined_hits: atomic<u32>,
    first_hit_plus_one: atomic<u32>,
}

@group(0) @binding(0)
var<storage, read> params: array<u32>; // [prefix_len, suffix_len, chunk_base, payload_len]
@group(0) @binding(1)
var<storage, read> prefix_buf: array<u32, 16>;
@group(0) @binding(2)
var<storage, read> suffix_buf: array<u32, 16>;
@group(0) @binding(3)
var<storage, read_write> results: ProbeResults;

fn base58_char(idx: u32) -> u32 {
    let alphabet = array<u32, 58>(
        49u,50u,51u,52u,53u,54u,55u,56u,57u,
        65u,66u,67u,68u,69u,70u,71u,72u,74u,75u,76u,77u,78u,80u,81u,82u,83u,84u,85u,86u,87u,88u,89u,90u,
        97u,98u,99u,100u,101u,102u,103u,104u,105u,106u,107u,109u,110u,111u,112u,113u,114u,115u,116u,117u,118u,119u,120u,121u,122u
    );
    return alphabet[idx % 58u];
}

fn pseudo_payload_char(candidate_index: u32, pos: u32) -> u32 {
    var x = candidate_index ^ (pos * 2654435761u);
    x = x * 1664525u + 1013904223u;
    x = x ^ (x >> 16u);
    return base58_char(x % 58u);
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let prefix_len = params[0];
    let suffix_len = params[1];
    let chunk_base = params[2];
    let payload_len = params[3];
    let candidate_index = chunk_base + gid.x;

    atomicAdd(&results.attempts, 1u);

    var prefix_ok = true;
    var i = 0u;
    loop {
        if (i >= prefix_len || i >= 16u) { break; }
        if (pseudo_payload_char(candidate_index, i) != prefix_buf[i]) {
            prefix_ok = false;
            break;
        }
        i = i + 1u;
    }

    var suffix_ok = true;
    var j = 0u;
    loop {
        if (j >= suffix_len || j >= 16u) { break; }
        let pos = payload_len - suffix_len + j;
        if (pseudo_payload_char(candidate_index, pos) != suffix_buf[j]) {
            suffix_ok = false;
            break;
        }
        j = j + 1u;
    }

    let prefix_match = (prefix_len == 0u) || prefix_ok;
    let suffix_match = (suffix_len == 0u) || suffix_ok;

    if (prefix_match) { atomicAdd(&results.prefix_hits, 1u); }
    if (suffix_match) { atomicAdd(&results.suffix_hits, 1u); }

    if (prefix_match && suffix_match) {
        atomicAdd(&results.combined_hits, 1u);
        if (atomicLoad(&results.first_hit_plus_one) == 0u) {
            let _ = atomicCompareExchangeWeak(&results.first_hit_plus_one, 0u, candidate_index + 1u);
        }
    }
}
"#;

    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("wallet-cli-gpu-vanity-probe-shader"),
        source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(shader_src)),
    });

    let params_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-probe-params"),
        size: (4 * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let prefix_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-probe-prefix"),
        size: (VANITY_PROBE_MAX_PATTERN_LEN * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let suffix_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-probe-suffix"),
        size: (VANITY_PROBE_MAX_PATTERN_LEN * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let results_word_count = 5usize;
    let results_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-probe-results"),
        size: (results_word_count * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let readback = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-probe-readback"),
        size: (results_word_count * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
        mapped_at_creation: false,
    });

    queue.write_buffer(&prefix_buffer, 0, &u32_slice_to_le_bytes(&prefix_words));
    queue.write_buffer(&suffix_buffer, 0, &u32_slice_to_le_bytes(&suffix_words));
    queue.write_buffer(&results_buffer, 0, &u32_slice_to_le_bytes(&[0u32; 5]));

    let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("wallet-cli-gpu-vanity-probe-bgl"),
        entries: &[
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 2,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 3,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
        ],
    });
    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("wallet-cli-gpu-vanity-probe-pipeline-layout"),
        bind_group_layouts: &[&bind_group_layout],
        push_constant_ranges: &[],
    });
    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("wallet-cli-gpu-vanity-probe-pipeline"),
        layout: Some(&pipeline_layout),
        module: &shader,
        entry_point: "main",
    });
    let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("wallet-cli-gpu-vanity-probe-bind-group"),
        layout: &bind_group_layout,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: params_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: prefix_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 2,
                resource: suffix_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 3,
                resource: results_buffer.as_entire_binding(),
            },
        ],
    });

    println!(
        "Vanity probe config: chunks={}, workgroups/chunk={}, prefix={:?}, suffix={:?}",
        config.chunks, config.workgroups_per_chunk, config.prefix, config.suffix
    );

    let start = Instant::now();
    for chunk_idx in 0..config.chunks {
        let chunk_base = (chunk_idx as u64 * invocations_per_chunk) as u32;
        let params = [
            prefix_len as u32,
            suffix_len as u32,
            chunk_base,
            VANITY_PROBE_PAYLOAD_LEN,
        ];
        queue.write_buffer(&params_buffer, 0, &u32_slice_to_le_bytes(&params));

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("wallet-cli-gpu-vanity-probe-encoder"),
        });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("wallet-cli-gpu-vanity-probe-pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(config.workgroups_per_chunk, 1, 1);
        }
        queue.submit(Some(encoder.finish()));

        if config.chunks <= 8 || chunk_idx + 1 == config.chunks {
            let done = chunk_idx + 1;
            println!(
                "GPU vanity probe chunk {done}/{} submitted (base={}, workgroups/chunk={})",
                config.chunks, chunk_base, config.workgroups_per_chunk
            );
        }
    }

    let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
        label: Some("wallet-cli-gpu-vanity-probe-readback-encoder"),
    });
    encoder.copy_buffer_to_buffer(
        &results_buffer,
        0,
        &readback,
        0,
        (results_word_count * std::mem::size_of::<u32>()) as u64,
    );
    queue.submit(Some(encoder.finish()));

    let (tx, rx) = mpsc::channel();
    readback
        .slice(..)
        .map_async(wgpu::MapMode::Read, move |res| {
            let _ = tx.send(res);
        });
    let _ = device.poll(wgpu::Maintain::Wait);

    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("readback map failed: {}", e)),
        Err(_) => return Err("Timed out waiting for vanity probe readback".to_string()),
    }

    let mapped = readback.slice(..).get_mapped_range();
    let words = parse_u32_vec_le(&mapped);
    drop(mapped);
    readback.unmap();
    if words.len() < results_word_count {
        return Err(format!(
            "Unexpected vanity probe result size: {} words",
            words.len()
        ));
    }

    let elapsed = start.elapsed();
    let attempts = words[0] as u64;
    let prefix_hits = words[1] as u64;
    let suffix_hits = words[2] as u64;
    let combined_hits = words[3] as u64;
    let first_hit_index = match words[4] {
        0 => None,
        n => Some((n - 1) as u64),
    };

    if attempts != total_candidates {
        return Err(format!(
            "GPU vanity probe attempt mismatch: got {}, expected {}",
            attempts, total_candidates
        ));
    }

    println!(
        "GPU vanity probe passed. candidates={} prefix_hits={} suffix_hits={} combined_hits={} elapsed={:.3}s",
        total_candidates,
        prefix_hits,
        suffix_hits,
        combined_hits,
        elapsed.as_secs_f64()
    );

    Ok(GpuVanityProbeResult {
        total_candidates,
        prefix_hits,
        suffix_hits,
        combined_hits,
        first_hit_index,
        elapsed,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct GpuVanityJobPipelineConfig {
    pub(crate) chunks: u32,
    pub(crate) workgroups_per_chunk: u32,
    pub(crate) prefix: Option<String>,
    pub(crate) suffix: Option<String>,
    pub(crate) max_hits: u32,
    pub(crate) stop_after_hits: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct GpuVanityJobPipelineResult {
    pub(crate) total_candidates: u64,
    pub(crate) attempts: u64,
    pub(crate) prefix_hits: u64,
    pub(crate) suffix_hits: u64,
    pub(crate) combined_hits: u64,
    pub(crate) hit_count: u64,
    pub(crate) stop_flag_triggered: bool,
    pub(crate) stored_hit_indices: Vec<u64>,
    pub(crate) verified_stored_hits: u64,
    pub(crate) verification_mismatches: u64,
    pub(crate) elapsed: Duration,
}

pub(crate) fn gpu_vanity_job_pipeline_test(
    requested_index: Option<usize>,
    config: &GpuVanityJobPipelineConfig,
) -> Result<GpuVanityJobPipelineResult, String> {
    if config.chunks == 0 {
        return Err("chunks must be > 0".to_string());
    }
    if config.workgroups_per_chunk == 0 {
        return Err("workgroups_per_chunk must be > 0".to_string());
    }
    if config.max_hits == 0 {
        return Err("max_hits must be > 0".to_string());
    }
    if config.max_hits as usize > VANITY_JOB_MAX_HITS {
        return Err(format!("max_hits must be <= {}", VANITY_JOB_MAX_HITS));
    }

    let prefix_len = config.prefix.as_ref().map(|s| s.len()).unwrap_or(0);
    let suffix_len = config.suffix.as_ref().map(|s| s.len()).unwrap_or(0);
    if prefix_len > VANITY_JOB_MAX_PATTERN_LEN {
        return Err(format!(
            "prefix too long for job test (max {})",
            VANITY_JOB_MAX_PATTERN_LEN
        ));
    }
    if suffix_len > VANITY_JOB_MAX_PATTERN_LEN {
        return Err(format!(
            "suffix too long for job test (max {})",
            VANITY_JOB_MAX_PATTERN_LEN
        ));
    }
    if (prefix_len + suffix_len) as u32 > VANITY_JOB_PAYLOAD_LEN {
        return Err(format!(
            "prefix+suffix too long for job test payload (max {} total chars)",
            VANITY_JOB_PAYLOAD_LEN
        ));
    }

    let invocations_per_chunk =
        config.workgroups_per_chunk as u64 * VANITY_JOB_WORKGROUP_SIZE as u64;
    let total_candidates = config.chunks as u64 * invocations_per_chunk;
    if total_candidates > u32::MAX as u64 {
        return Err(format!(
            "Requested total candidates {} exceeds current u32 job-test limit",
            total_candidates
        ));
    }

    let prefix_words = parse_vanity_probe_pattern("prefix", config.prefix.as_deref())?;
    let suffix_words = parse_vanity_probe_pattern("suffix", config.suffix.as_deref())?;

    let (selected_idx, summary, adapter) = select_adapter_for_run(requested_index)?;
    print_adapter_banner("GPU vanity job test on", selected_idx, &summary);
    let (device, queue) = request_compute_device(&adapter, "wallet-cli-gpu-vanity-job-test")?;

    let shader_src = r#"
struct Counters {
    attempts: atomic<u32>,
    prefix_hits: atomic<u32>,
    suffix_hits: atomic<u32>,
    combined_hits: atomic<u32>,
    hit_count: atomic<u32>,
}

struct StopFlag {
    value: atomic<u32>,
}

@group(0) @binding(0)
var<storage, read> params: array<u32>; // [prefix_len, suffix_len, payload_len, max_hits]
@group(0) @binding(1)
var<storage, read> work_item: array<u32>; // [start_index, candidate_count, stop_after_hits, reserved]
@group(0) @binding(2)
var<storage, read> prefix_buf: array<u32, 16>;
@group(0) @binding(3)
var<storage, read> suffix_buf: array<u32, 16>;
@group(0) @binding(4)
var<storage, read> candidate_payloads: array<u32>;
@group(0) @binding(5)
var<storage, read_write> counters: Counters;
@group(0) @binding(6)
var<storage, read_write> stop_flag: StopFlag;
@group(0) @binding(7)
var<storage, read_write> hit_indices: array<u32, 64>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let prefix_len = params[0];
    let suffix_len = params[1];
    let payload_len = params[2];
    let max_hits = params[3];

    let start_index = work_item[0];
    let candidate_count = work_item[1];
    let stop_after_hits = work_item[2];

    if (gid.x >= candidate_count) {
        return;
    }

    if (atomicLoad(&stop_flag.value) != 0u) {
        return;
    }

    let candidate_index = start_index + gid.x;
    let payload_base = gid.x * payload_len;
    atomicAdd(&counters.attempts, 1u);

    var prefix_ok = true;
    var i = 0u;
    loop {
        if (i >= prefix_len || i >= 16u) { break; }
        if (candidate_payloads[payload_base + i] != prefix_buf[i]) {
            prefix_ok = false;
            break;
        }
        i = i + 1u;
    }

    var suffix_ok = true;
    var j = 0u;
    loop {
        if (j >= suffix_len || j >= 16u) { break; }
        let pos = payload_len - suffix_len + j;
        if (candidate_payloads[payload_base + pos] != suffix_buf[j]) {
            suffix_ok = false;
            break;
        }
        j = j + 1u;
    }

    let prefix_match = (prefix_len == 0u) || prefix_ok;
    let suffix_match = (suffix_len == 0u) || suffix_ok;

    if (prefix_match) { atomicAdd(&counters.prefix_hits, 1u); }
    if (suffix_match) { atomicAdd(&counters.suffix_hits, 1u); }

    if (prefix_match && suffix_match) {
        atomicAdd(&counters.combined_hits, 1u);
        let slot = atomicAdd(&counters.hit_count, 1u);
        if (slot < max_hits) {
            hit_indices[slot] = candidate_index;
        }
        if (stop_after_hits > 0u && (slot + 1u) >= stop_after_hits) {
            atomicStore(&stop_flag.value, 1u);
        }
    }
}
"#;

    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-test-shader"),
        source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(shader_src)),
    });

    let params_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-params"),
        size: (4 * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let work_item_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-work-item"),
        size: (4 * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let prefix_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-prefix"),
        size: (VANITY_JOB_MAX_PATTERN_LEN * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let suffix_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-suffix"),
        size: (VANITY_JOB_MAX_PATTERN_LEN * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let candidate_payloads_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-candidate-payloads"),
        size: (invocations_per_chunk
            * VANITY_JOB_PAYLOAD_LEN as u64
            * std::mem::size_of::<u32>() as u64),
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let counters_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-counters"),
        size: (5 * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let stop_flag_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-stop-flag"),
        size: std::mem::size_of::<u32>() as u64,
        usage: wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let hit_indices_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-hit-indices"),
        size: (VANITY_JOB_MAX_HITS * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let counters_readback = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-counters-readback"),
        size: (5 * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
        mapped_at_creation: false,
    });
    let stop_readback = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-stop-readback"),
        size: std::mem::size_of::<u32>() as u64,
        usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
        mapped_at_creation: false,
    });
    let hits_readback = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-hits-readback"),
        size: (VANITY_JOB_MAX_HITS * std::mem::size_of::<u32>()) as u64,
        usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
        mapped_at_creation: false,
    });

    queue.write_buffer(&prefix_buffer, 0, &u32_slice_to_le_bytes(&prefix_words));
    queue.write_buffer(&suffix_buffer, 0, &u32_slice_to_le_bytes(&suffix_words));
    queue.write_buffer(
        &params_buffer,
        0,
        &u32_slice_to_le_bytes(&[
            prefix_len as u32,
            suffix_len as u32,
            VANITY_JOB_PAYLOAD_LEN,
            config.max_hits,
        ]),
    );
    queue.write_buffer(&counters_buffer, 0, &u32_slice_to_le_bytes(&[0u32; 5]));
    queue.write_buffer(&stop_flag_buffer, 0, &0u32.to_le_bytes());
    queue.write_buffer(
        &hit_indices_buffer,
        0,
        &u32_slice_to_le_bytes(&[0u32; VANITY_JOB_MAX_HITS]),
    );

    let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-bgl"),
        entries: &[
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 2,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 3,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 4,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 5,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 6,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 7,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
        ],
    });
    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-pipeline-layout"),
        bind_group_layouts: &[&bind_group_layout],
        push_constant_ranges: &[],
    });
    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-pipeline"),
        layout: Some(&pipeline_layout),
        module: &shader,
        entry_point: "main",
    });
    let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-bind-group"),
        layout: &bind_group_layout,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: params_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: work_item_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 2,
                resource: prefix_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 3,
                resource: suffix_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 4,
                resource: candidate_payloads_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 5,
                resource: counters_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 6,
                resource: stop_flag_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 7,
                resource: hit_indices_buffer.as_entire_binding(),
            },
        ],
    });

    println!(
        "Vanity job test config: chunks={}, workgroups/chunk={}, prefix={:?}, suffix={:?}, max_hits={}, stop_after_hits={}",
        config.chunks,
        config.workgroups_per_chunk,
        config.prefix,
        config.suffix,
        config.max_hits,
        config.stop_after_hits
    );

    let start = Instant::now();
    for chunk_idx in 0..config.chunks {
        let chunk_start = (chunk_idx as u64 * invocations_per_chunk) as u32;
        let work_item_words = [
            chunk_start,
            invocations_per_chunk as u32,
            config.stop_after_hits,
            0u32,
        ];
        queue.write_buffer(
            &work_item_buffer,
            0,
            &u32_slice_to_le_bytes(&work_item_words),
        );
        let candidate_payload_words = build_pseudo_payload_chunk_words(
            chunk_start,
            invocations_per_chunk as u32,
            VANITY_JOB_PAYLOAD_LEN,
        );
        queue.write_buffer(
            &candidate_payloads_buffer,
            0,
            &u32_slice_to_le_bytes(&candidate_payload_words),
        );

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("wallet-cli-gpu-vanity-job-encoder"),
        });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("wallet-cli-gpu-vanity-job-pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(config.workgroups_per_chunk, 1, 1);
        }
        queue.submit(Some(encoder.finish()));

        let _ = device.poll(wgpu::Maintain::Poll);

        if config.chunks <= 8 || chunk_idx + 1 == config.chunks {
            let done = chunk_idx + 1;
            println!(
                "GPU vanity job chunk {done}/{} submitted (start={}, candidates/chunk={})",
                config.chunks, chunk_start, invocations_per_chunk
            );
        }

        if config.stop_after_hits > 0 {
            let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wallet-cli-gpu-vanity-job-stop-check-encoder"),
            });
            encoder.copy_buffer_to_buffer(
                &stop_flag_buffer,
                0,
                &stop_readback,
                0,
                std::mem::size_of::<u32>() as u64,
            );
            queue.submit(Some(encoder.finish()));

            let (tx, rx) = mpsc::channel();
            stop_readback
                .slice(..)
                .map_async(wgpu::MapMode::Read, move |res| {
                    let _ = tx.send(res);
                });
            let _ = device.poll(wgpu::Maintain::Wait);
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(format!("stop flag map failed: {}", e)),
                Err(_) => return Err("Timed out waiting for stop flag readback".to_string()),
            }
            let mapped = stop_readback.slice(..).get_mapped_range();
            let stop_words = parse_u32_vec_le(&mapped);
            drop(mapped);
            stop_readback.unmap();
            if stop_words.first().copied().unwrap_or_default() != 0 {
                println!(
                    "GPU vanity job stop flag triggered after chunk {}",
                    chunk_idx + 1
                );
                break;
            }
        }
    }

    let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
        label: Some("wallet-cli-gpu-vanity-job-readback-encoder"),
    });
    encoder.copy_buffer_to_buffer(
        &counters_buffer,
        0,
        &counters_readback,
        0,
        (5 * std::mem::size_of::<u32>()) as u64,
    );
    encoder.copy_buffer_to_buffer(
        &stop_flag_buffer,
        0,
        &stop_readback,
        0,
        std::mem::size_of::<u32>() as u64,
    );
    encoder.copy_buffer_to_buffer(
        &hit_indices_buffer,
        0,
        &hits_readback,
        0,
        (VANITY_JOB_MAX_HITS * std::mem::size_of::<u32>()) as u64,
    );
    queue.submit(Some(encoder.finish()));

    let (tx_c, rx_c) = mpsc::channel();
    counters_readback
        .slice(..)
        .map_async(wgpu::MapMode::Read, move |res| {
            let _ = tx_c.send(res);
        });
    let (tx_s, rx_s) = mpsc::channel();
    stop_readback
        .slice(..)
        .map_async(wgpu::MapMode::Read, move |res| {
            let _ = tx_s.send(res);
        });
    let (tx_h, rx_h) = mpsc::channel();
    hits_readback
        .slice(..)
        .map_async(wgpu::MapMode::Read, move |res| {
            let _ = tx_h.send(res);
        });
    let _ = device.poll(wgpu::Maintain::Wait);

    match rx_c.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("counters readback map failed: {}", e)),
        Err(_) => return Err("Timed out waiting for counters readback".to_string()),
    }
    match rx_s.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("stop readback map failed: {}", e)),
        Err(_) => return Err("Timed out waiting for stop readback".to_string()),
    }
    match rx_h.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("hits readback map failed: {}", e)),
        Err(_) => return Err("Timed out waiting for hits readback".to_string()),
    }

    let counters_words = {
        let mapped = counters_readback.slice(..).get_mapped_range();
        let words = parse_u32_vec_le(&mapped);
        drop(mapped);
        counters_readback.unmap();
        words
    };
    let stop_words = {
        let mapped = stop_readback.slice(..).get_mapped_range();
        let words = parse_u32_vec_le(&mapped);
        drop(mapped);
        stop_readback.unmap();
        words
    };
    let hit_words = {
        let mapped = hits_readback.slice(..).get_mapped_range();
        let words = parse_u32_vec_le(&mapped);
        drop(mapped);
        hits_readback.unmap();
        words
    };

    if counters_words.len() < 5 {
        return Err(format!(
            "Unexpected counters result size: {} words",
            counters_words.len()
        ));
    }

    let elapsed = start.elapsed();
    let attempts = counters_words[0] as u64;
    let prefix_hits = counters_words[1] as u64;
    let suffix_hits = counters_words[2] as u64;
    let combined_hits = counters_words[3] as u64;
    let hit_count = counters_words[4] as u64;
    let stop_flag_triggered = stop_words.first().copied().unwrap_or_default() != 0;
    let stored_count = (hit_count
        .min(config.max_hits as u64)
        .min(VANITY_JOB_MAX_HITS as u64)) as usize;
    let stored_hit_indices = hit_words
        .iter()
        .take(stored_count)
        .map(|v| *v as u64)
        .collect::<Vec<_>>();
    let mut verified_stored_hits = 0u64;
    let mut verification_mismatches = 0u64;
    for idx in &stored_hit_indices {
        let idx32: u32 = (*idx)
            .try_into()
            .map_err(|_| format!("hit index out of u32 range: {}", idx))?;
        if pseudo_payload_matches_host(idx32, config.prefix.as_deref(), config.suffix.as_deref()) {
            verified_stored_hits += 1;
        } else {
            verification_mismatches += 1;
        }
    }

    if attempts > total_candidates {
        return Err(format!(
            "GPU vanity job attempts {} exceeded total candidates {}",
            attempts, total_candidates
        ));
    }
    if combined_hits != hit_count {
        return Err(format!(
            "GPU vanity job mismatch: combined_hits={} hit_count={}",
            combined_hits, hit_count
        ));
    }
    if verification_mismatches > 0 {
        return Err(format!(
            "GPU vanity job verification mismatch: {} of {} stored hits failed host verification",
            verification_mismatches,
            stored_hit_indices.len()
        ));
    }

    println!(
        "GPU vanity job test passed. attempts={} / {} prefix_hits={} suffix_hits={} combined_hits={} stored_hits={} verified_hits={} stop_flag={} elapsed={:.3}s",
        attempts,
        total_candidates,
        prefix_hits,
        suffix_hits,
        combined_hits,
        stored_hit_indices.len(),
        verified_stored_hits,
        stop_flag_triggered,
        elapsed.as_secs_f64()
    );

    Ok(GpuVanityJobPipelineResult {
        total_candidates,
        attempts,
        prefix_hits,
        suffix_hits,
        combined_hits,
        hit_count,
        stop_flag_triggered,
        stored_hit_indices,
        verified_stored_hits,
        verification_mismatches,
        elapsed,
    })
}

pub(crate) struct GpuPayloadBatchFilterConfig {
    pub(crate) prefix: Option<String>,
    pub(crate) suffix: Option<String>,
    pub(crate) max_hits: u32,
    pub(crate) stop_after_hits: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct GpuPayloadBatchFilterResult {
    pub(crate) candidate_count: u32,
    pub(crate) attempts: u64,
    pub(crate) prefix_hits: u64,
    pub(crate) suffix_hits: u64,
    pub(crate) combined_hits: u64,
    pub(crate) hit_count: u64,
    pub(crate) stop_flag_triggered: bool,
    pub(crate) stored_hit_indices: Vec<u32>,
    pub(crate) verified_stored_hits: u64,
    pub(crate) verification_mismatches: u64,
    pub(crate) elapsed: Duration,
}

pub(crate) struct GpuPayloadBatchFilterSession {
    payload_len: usize,
    max_candidates: u32,
    device: Arc<wgpu::Device>,
    queue: Arc<wgpu::Queue>,
    params_buffer: wgpu::Buffer,
    prefix_buffer: wgpu::Buffer,
    suffix_buffer: wgpu::Buffer,
    candidate_payloads_buffer: wgpu::Buffer,
    counters_buffer: wgpu::Buffer,
    stop_flag_buffer: wgpu::Buffer,
    hit_indices_buffer: wgpu::Buffer,
    counters_readback: wgpu::Buffer,
    stop_readback: wgpu::Buffer,
    hits_readback: wgpu::Buffer,
    pipeline: wgpu::ComputePipeline,
    bind_group: wgpu::BindGroup,
}

impl GpuPayloadBatchFilterSession {
    pub(crate) fn new(
        requested_index: Option<usize>,
        payload_len: usize,
        max_candidates: u32,
    ) -> Result<Self, String> {
        let runtime = GpuComputeRuntime::new(
            requested_index,
            "GPU payload filter session on",
            "wallet-cli-gpu-payload-filter",
        )?;
        Self::new_with_runtime(&runtime, payload_len, max_candidates)
    }

    pub(crate) fn new_with_runtime(
        runtime: &GpuComputeRuntime,
        payload_len: usize,
        max_candidates: u32,
    ) -> Result<Self, String> {
        if payload_len == 0 {
            return Err("payload length must be > 0".to_string());
        }
        if payload_len > GPU_FILTER_BATCH_MAX_PAYLOAD_LEN {
            return Err(format!(
                "payload length {} exceeds GPU filter batch limit {}",
                payload_len, GPU_FILTER_BATCH_MAX_PAYLOAD_LEN
            ));
        }
        if max_candidates == 0 {
            return Err("max_candidates must be > 0".to_string());
        }

        let device = Arc::clone(&runtime.device);
        let queue = Arc::clone(&runtime.queue);

        let shader_src = r#"
struct Counters {
    attempts: atomic<u32>,
    prefix_hits: atomic<u32>,
    suffix_hits: atomic<u32>,
    combined_hits: atomic<u32>,
    hit_count: atomic<u32>,
}

struct StopFlag {
    value: atomic<u32>,
}

@group(0) @binding(0)
var<storage, read> params: array<u32>; // [prefix_len, suffix_len, payload_len, candidate_count, max_hits, stop_after_hits]
@group(0) @binding(1)
var<storage, read> prefix_buf: array<u32, 16>;
@group(0) @binding(2)
var<storage, read> suffix_buf: array<u32, 16>;
@group(0) @binding(3)
var<storage, read> candidate_payloads: array<u32>;
@group(0) @binding(4)
var<storage, read_write> counters: Counters;
@group(0) @binding(5)
var<storage, read_write> stop_flag: StopFlag;
@group(0) @binding(6)
var<storage, read_write> hit_indices: array<u32, 64>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let prefix_len = params[0];
    let suffix_len = params[1];
    let payload_len = params[2];
    let candidate_count = params[3];
    let max_hits = params[4];
    let stop_after_hits = params[5];

    let idx = gid.x;
    if (idx >= candidate_count) {
        return;
    }
    if (atomicLoad(&stop_flag.value) != 0u) {
        return;
    }

    atomicAdd(&counters.attempts, 1u);
    let payload_base = idx * payload_len;

    var prefix_ok = true;
    var i = 0u;
    loop {
        if (i >= prefix_len || i >= 16u) { break; }
        if (candidate_payloads[payload_base + i] != prefix_buf[i]) {
            prefix_ok = false;
            break;
        }
        i = i + 1u;
    }

    var suffix_ok = true;
    var j = 0u;
    loop {
        if (j >= suffix_len || j >= 16u) { break; }
        let pos = payload_len - suffix_len + j;
        if (candidate_payloads[payload_base + pos] != suffix_buf[j]) {
            suffix_ok = false;
            break;
        }
        j = j + 1u;
    }

    let prefix_match = (prefix_len == 0u) || prefix_ok;
    let suffix_match = (suffix_len == 0u) || suffix_ok;

    if (prefix_match) { atomicAdd(&counters.prefix_hits, 1u); }
    if (suffix_match) { atomicAdd(&counters.suffix_hits, 1u); }

    if (prefix_match && suffix_match) {
        atomicAdd(&counters.combined_hits, 1u);
        let slot = atomicAdd(&counters.hit_count, 1u);
        if (slot < max_hits) {
            hit_indices[slot] = idx;
        }
        if (stop_after_hits > 0u && (slot + 1u) >= stop_after_hits) {
            atomicStore(&stop_flag.value, 1u);
        }
    }
}
"#;

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-shader"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(shader_src)),
        });

        let params_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-params"),
            size: (6 * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let prefix_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-prefix"),
            size: (VANITY_JOB_MAX_PATTERN_LEN * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let suffix_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-suffix"),
            size: (VANITY_JOB_MAX_PATTERN_LEN * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let candidate_payloads_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-candidates"),
            size: (max_candidates as u64 * payload_len as u64 * std::mem::size_of::<u32>() as u64),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let counters_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-counters"),
            size: (5 * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let stop_flag_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-stop"),
            size: std::mem::size_of::<u32>() as u64,
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let hit_indices_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-hits"),
            size: (VANITY_JOB_MAX_HITS * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let counters_readback = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-counters-readback"),
            size: (5 * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let stop_readback = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-stop-readback"),
            size: std::mem::size_of::<u32>() as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let hits_readback = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-hits-readback"),
            size: (VANITY_JOB_MAX_HITS * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-bgl"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 3,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 4,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 5,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 6,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-pipeline-layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: "main",
        });
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("wallet-cli-gpu-payload-filter-bind-group"),
            layout: &bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: params_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: prefix_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: suffix_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: candidate_payloads_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 4,
                    resource: counters_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 5,
                    resource: stop_flag_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 6,
                    resource: hit_indices_buffer.as_entire_binding(),
                },
            ],
        });

        Ok(Self {
            payload_len,
            max_candidates,
            device,
            queue,
            params_buffer,
            prefix_buffer,
            suffix_buffer,
            candidate_payloads_buffer,
            counters_buffer,
            stop_flag_buffer,
            hit_indices_buffer,
            counters_readback,
            stop_readback,
            hits_readback,
            pipeline,
            bind_group,
        })
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn max_candidates(&self) -> u32 {
        self.max_candidates
    }

    pub(crate) fn filter_batch(
        &mut self,
        payloads: &[String],
        config: &GpuPayloadBatchFilterConfig,
    ) -> Result<GpuPayloadBatchFilterResult, String> {
        if payloads.is_empty() {
            return Err("payload batch is empty".to_string());
        }
        if config.max_hits == 0 {
            return Err("max_hits must be > 0".to_string());
        }
        if config.max_hits as usize > VANITY_JOB_MAX_HITS {
            return Err(format!("max_hits must be <= {}", VANITY_JOB_MAX_HITS));
        }
        let payload_len = payloads[0].len();
        if payload_len == 0 {
            return Err("payload length must be > 0".to_string());
        }
        if payload_len > GPU_FILTER_BATCH_MAX_PAYLOAD_LEN {
            return Err(format!(
                "payload length {} exceeds GPU filter batch limit {}",
                payload_len, GPU_FILTER_BATCH_MAX_PAYLOAD_LEN
            ));
        }
        if payload_len != self.payload_len {
            return Err(format!(
                "payload length {} does not match session payload length {}",
                payload_len, self.payload_len
            ));
        }
        if payloads.iter().any(|p| p.len() != payload_len) {
            return Err("all payloads in batch must have identical length".to_string());
        }
        if payloads.iter().any(|p| !p.is_ascii()) {
            return Err("all payloads in batch must be ASCII".to_string());
        }
        if payloads.len() > self.max_candidates as usize {
            return Err(format!(
                "payload batch too large for session ({} > {})",
                payloads.len(),
                self.max_candidates
            ));
        }

        let prefix_len = config.prefix.as_ref().map(|s| s.len()).unwrap_or(0);
        let suffix_len = config.suffix.as_ref().map(|s| s.len()).unwrap_or(0);
        if prefix_len > VANITY_JOB_MAX_PATTERN_LEN {
            return Err(format!(
                "prefix too long for GPU filter (max {})",
                VANITY_JOB_MAX_PATTERN_LEN
            ));
        }
        if suffix_len > VANITY_JOB_MAX_PATTERN_LEN {
            return Err(format!(
                "suffix too long for GPU filter (max {})",
                VANITY_JOB_MAX_PATTERN_LEN
            ));
        }
        if prefix_len + suffix_len > payload_len {
            return Err("prefix+suffix longer than payload length".to_string());
        }

        let prefix_words = parse_vanity_probe_pattern("prefix", config.prefix.as_deref())?;
        let suffix_words = parse_vanity_probe_pattern("suffix", config.suffix.as_deref())?;
        let candidate_count = payloads.len() as u32;

        let mut candidate_payload_words = Vec::with_capacity(payloads.len() * payload_len);
        for payload in payloads {
            for b in payload.as_bytes() {
                candidate_payload_words.push(*b as u32);
            }
        }

        self.queue.write_buffer(
            &self.prefix_buffer,
            0,
            &u32_slice_to_le_bytes(&prefix_words),
        );
        self.queue.write_buffer(
            &self.suffix_buffer,
            0,
            &u32_slice_to_le_bytes(&suffix_words),
        );
        self.queue.write_buffer(
            &self.params_buffer,
            0,
            &u32_slice_to_le_bytes(&[
                prefix_len as u32,
                suffix_len as u32,
                payload_len as u32,
                candidate_count,
                config.max_hits,
                config.stop_after_hits,
            ]),
        );
        self.queue.write_buffer(
            &self.candidate_payloads_buffer,
            0,
            &u32_slice_to_le_bytes(&candidate_payload_words),
        );
        self.queue
            .write_buffer(&self.counters_buffer, 0, &u32_slice_to_le_bytes(&[0u32; 5]));
        self.queue
            .write_buffer(&self.stop_flag_buffer, 0, &0u32.to_le_bytes());
        self.queue.write_buffer(
            &self.hit_indices_buffer,
            0,
            &u32_slice_to_le_bytes(&[0u32; VANITY_JOB_MAX_HITS]),
        );

        let dispatch_workgroups = candidate_count.div_ceil(64);
        let start = Instant::now();
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wallet-cli-gpu-payload-filter-encoder"),
            });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("wallet-cli-gpu-payload-filter-pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &self.bind_group, &[]);
            pass.dispatch_workgroups(dispatch_workgroups, 1, 1);
        }
        self.queue.submit(Some(encoder.finish()));
        let _ = self.device.poll(wgpu::Maintain::Poll);

        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wallet-cli-gpu-payload-filter-readback-encoder"),
            });
        encoder.copy_buffer_to_buffer(
            &self.counters_buffer,
            0,
            &self.counters_readback,
            0,
            (5 * std::mem::size_of::<u32>()) as u64,
        );
        encoder.copy_buffer_to_buffer(
            &self.stop_flag_buffer,
            0,
            &self.stop_readback,
            0,
            std::mem::size_of::<u32>() as u64,
        );
        encoder.copy_buffer_to_buffer(
            &self.hit_indices_buffer,
            0,
            &self.hits_readback,
            0,
            (VANITY_JOB_MAX_HITS * std::mem::size_of::<u32>()) as u64,
        );
        self.queue.submit(Some(encoder.finish()));

        let (tx_c, rx_c) = mpsc::channel();
        self.counters_readback
            .slice(..)
            .map_async(wgpu::MapMode::Read, move |res| {
                let _ = tx_c.send(res);
            });
        let (tx_s, rx_s) = mpsc::channel();
        self.stop_readback
            .slice(..)
            .map_async(wgpu::MapMode::Read, move |res| {
                let _ = tx_s.send(res);
            });
        let (tx_h, rx_h) = mpsc::channel();
        self.hits_readback
            .slice(..)
            .map_async(wgpu::MapMode::Read, move |res| {
                let _ = tx_h.send(res);
            });
        let _ = self.device.poll(wgpu::Maintain::Wait);

        match rx_c.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("counters readback map failed: {}", e)),
            Err(_) => return Err("Timed out waiting for counters readback".to_string()),
        }
        match rx_s.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("stop readback map failed: {}", e)),
            Err(_) => return Err("Timed out waiting for stop readback".to_string()),
        }
        match rx_h.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("hits readback map failed: {}", e)),
            Err(_) => return Err("Timed out waiting for hits readback".to_string()),
        }

        let counters_words = {
            let mapped = self.counters_readback.slice(..).get_mapped_range();
            let words = parse_u32_vec_le(&mapped);
            drop(mapped);
            self.counters_readback.unmap();
            words
        };
        let stop_words = {
            let mapped = self.stop_readback.slice(..).get_mapped_range();
            let words = parse_u32_vec_le(&mapped);
            drop(mapped);
            self.stop_readback.unmap();
            words
        };
        let hit_words = {
            let mapped = self.hits_readback.slice(..).get_mapped_range();
            let words = parse_u32_vec_le(&mapped);
            drop(mapped);
            self.hits_readback.unmap();
            words
        };

        if counters_words.len() < 5 {
            return Err(format!(
                "Unexpected counters result size: {} words",
                counters_words.len()
            ));
        }

        let elapsed = start.elapsed();
        let attempts = counters_words[0] as u64;
        let prefix_hits = counters_words[1] as u64;
        let suffix_hits = counters_words[2] as u64;
        let combined_hits = counters_words[3] as u64;
        let hit_count = counters_words[4] as u64;
        let stop_flag_triggered = stop_words.first().copied().unwrap_or_default() != 0;
        let stored_count = (hit_count
            .min(config.max_hits as u64)
            .min(VANITY_JOB_MAX_HITS as u64)) as usize;
        let stored_hit_indices = hit_words
            .iter()
            .take(stored_count)
            .copied()
            .collect::<Vec<_>>();

        let mut verified_stored_hits = 0u64;
        let mut verification_mismatches = 0u64;
        for idx in &stored_hit_indices {
            let payload = payloads
                .get(*idx as usize)
                .ok_or_else(|| format!("GPU returned out-of-range payload index {}", idx))?;
            if payload_matches_filters_host(
                payload,
                config.prefix.as_deref(),
                config.suffix.as_deref(),
            ) {
                verified_stored_hits += 1;
            } else {
                verification_mismatches += 1;
            }
        }

        if attempts > candidate_count as u64 {
            return Err(format!(
                "GPU payload filter attempts {} exceeded candidate count {}",
                attempts, candidate_count
            ));
        }
        if combined_hits != hit_count {
            return Err(format!(
                "GPU payload filter mismatch: combined_hits={} hit_count={}",
                combined_hits, hit_count
            ));
        }
        if verification_mismatches > 0 {
            return Err(format!(
                "GPU payload filter verification mismatch: {} of {} stored hits failed host verification",
                verification_mismatches,
                stored_hit_indices.len()
            ));
        }

        Ok(GpuPayloadBatchFilterResult {
            candidate_count,
            attempts,
            prefix_hits,
            suffix_hits,
            combined_hits,
            hit_count,
            stop_flag_triggered,
            stored_hit_indices,
            verified_stored_hits,
            verification_mismatches,
            elapsed,
        })
    }
}

pub(crate) fn gpu_filter_payload_batch(
    requested_index: Option<usize>,
    payloads: &[String],
    config: &GpuPayloadBatchFilterConfig,
) -> Result<GpuPayloadBatchFilterResult, String> {
    let Some(first) = payloads.first() else {
        return Err("payload batch is empty".to_string());
    };
    let mut session =
        GpuPayloadBatchFilterSession::new(requested_index, first.len(), payloads.len() as u32)?;
    session.filter_batch(payloads, config)
}
