#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenClDeviceSummary {
    pub(crate) platform_index: usize,
    pub(crate) device_index: usize,
    pub(crate) platform_name: String,
    pub(crate) platform_vendor: String,
    pub(crate) name: String,
    pub(crate) vendor: String,
    pub(crate) driver_version: String,
    pub(crate) version: String,
    pub(crate) device_type_bits: u64,
    pub(crate) device_type_label: String,
    pub(crate) max_compute_units: u32,
    pub(crate) max_clock_mhz: u32,
    pub(crate) global_mem_mib: u64,
}

#[cfg(feature = "opencl-backend")]
mod imp {
    use super::OpenClDeviceSummary;
    use opencl3::device::{
        CL_DEVICE_TYPE_ACCELERATOR, CL_DEVICE_TYPE_ALL, CL_DEVICE_TYPE_CPU, CL_DEVICE_TYPE_DEFAULT,
        CL_DEVICE_TYPE_GPU, Device,
    };
    use opencl3::platform::get_platforms;

    fn summarize_opencl_error(prefix: &str, err: impl std::fmt::Display) -> String {
        format!("{prefix}: {err}")
    }

    fn device_type_label(bits: u64) -> String {
        let mut labels = Vec::new();
        if bits & CL_DEVICE_TYPE_GPU != 0 {
            labels.push("GPU");
        }
        if bits & CL_DEVICE_TYPE_ACCELERATOR != 0 {
            labels.push("Accelerator");
        }
        if bits & CL_DEVICE_TYPE_CPU != 0 {
            labels.push("CPU");
        }
        if bits & CL_DEVICE_TYPE_DEFAULT != 0 {
            labels.push("Default");
        }
        if labels.is_empty() {
            labels.push("Other");
        }
        labels.join("|")
    }

    fn safe<T>(res: Result<T, impl std::fmt::Display>, fallback: T) -> T {
        match res {
            Ok(v) => v,
            Err(_) => fallback,
        }
    }

    fn opencl_device_score(dev: &OpenClDeviceSummary) -> i64 {
        let mut score = 0i64;
        if dev.device_type_bits & CL_DEVICE_TYPE_GPU != 0 {
            score += 1_000_000;
        } else if dev.device_type_bits & CL_DEVICE_TYPE_ACCELERATOR != 0 {
            score += 500_000;
        } else if dev.device_type_bits & CL_DEVICE_TYPE_CPU != 0 {
            score += 10_000;
        }
        score += (dev.max_compute_units as i64) * 100;
        score += dev.max_clock_mhz as i64;
        score += (dev.global_mem_mib.min(1_000_000) as i64) / 16;
        score
    }

    pub(crate) fn list_opencl_devices() -> Result<Vec<OpenClDeviceSummary>, String> {
        let platforms =
            get_platforms().map_err(|e| summarize_opencl_error("OpenCL init failed", e))?;
        let mut out = Vec::new();

        for (platform_index, platform) in platforms.iter().enumerate() {
            let platform_name = safe(platform.name(), "<unknown platform>".to_string());
            let platform_vendor = safe(platform.vendor(), "<unknown vendor>".to_string());

            let device_ids = match platform.get_devices(CL_DEVICE_TYPE_ALL) {
                Ok(ids) => ids,
                Err(_) => continue,
            };

            for (device_index, device_id) in device_ids.iter().enumerate() {
                let device = Device::new(*device_id);
                let device_type_bits = safe(device.dev_type(), 0) as u64;
                let max_compute_units = safe(device.max_compute_units(), 0);
                let max_clock_mhz = safe(device.max_clock_frequency(), 0);
                let global_mem_mib = (safe(device.global_mem_size(), 0) as u64) / (1024 * 1024);
                out.push(OpenClDeviceSummary {
                    platform_index,
                    device_index,
                    platform_name: platform_name.clone(),
                    platform_vendor: platform_vendor.clone(),
                    name: safe(device.name(), "<unknown device>".to_string()),
                    vendor: safe(device.vendor(), "<unknown vendor>".to_string()),
                    driver_version: safe(device.driver_version(), String::new()),
                    version: safe(device.version(), String::new()),
                    device_type_bits,
                    device_type_label: device_type_label(device_type_bits),
                    max_compute_units,
                    max_clock_mhz,
                    global_mem_mib,
                });
            }
        }

        Ok(out)
    }

    pub(crate) fn select_best_opencl_device(
        devices: &[OpenClDeviceSummary],
    ) -> Option<OpenClDeviceSummary> {
        devices
            .iter()
            .max_by_key(|d| opencl_device_score(d))
            .cloned()
    }

    fn select_best_opencl_device_index(devices: &[OpenClDeviceSummary]) -> Option<usize> {
        devices
            .iter()
            .enumerate()
            .max_by_key(|(_, d)| opencl_device_score(d))
            .map(|(idx, _)| idx)
    }

    pub(crate) fn print_opencl_info() {
        match list_opencl_devices() {
            Ok(devices) => {
                if devices.is_empty() {
                    println!("No OpenCL devices detected.");
                    return;
                }
                let best_idx = select_best_opencl_device_index(&devices);
                println!("Detected {} OpenCL device(s):", devices.len());
                for (idx, dev) in devices.iter().enumerate() {
                    let marker = if Some(idx) == best_idx { "*" } else { " " };
                    println!(
                        "{} [{}] {} | vendor={} | type={} | CU={} | clock={}MHz | mem={} MiB",
                        marker,
                        idx,
                        dev.name,
                        dev.vendor,
                        dev.device_type_label,
                        dev.max_compute_units,
                        dev.max_clock_mhz,
                        dev.global_mem_mib
                    );
                    println!(
                        "    platform[{}:{}]: {} | vendor={}",
                        dev.platform_index,
                        dev.device_index,
                        dev.platform_name,
                        dev.platform_vendor
                    );
                    if !dev.driver_version.is_empty() {
                        println!("    driver: {}", dev.driver_version);
                    }
                    if !dev.version.is_empty() {
                        println!("    version: {}", dev.version);
                    }
                }
                if let Some(best) = best_idx.and_then(|idx| devices.get(idx)) {
                    println!(
                        "Selected by ranking: [{}] {} ({}, CU={}, mem={} MiB)",
                        best_idx.unwrap_or(0),
                        best.name,
                        best.device_type_label,
                        best.max_compute_units,
                        best.global_mem_mib
                    );
                }
            }
            Err(err) => println!("OpenCL device query failed: {}", err),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn opencl_hash_pubkey_batch() -> Result<(), String> {
        Err("OpenCL pubkey SHA-256 kernel not implemented yet".to_string())
    }

    #[allow(dead_code)]
    pub(crate) fn opencl_filter_payload_batch() -> Result<(), String> {
        Err("OpenCL payload filter kernel not implemented yet".to_string())
    }
}

#[cfg(not(feature = "opencl-backend"))]
mod imp {
    use super::OpenClDeviceSummary;

    const OPENCL_DISABLED_MSG: &str =
        "OpenCL backend is not enabled in this build. Rebuild with `--features opencl-backend`.";

    pub(crate) fn list_opencl_devices() -> Result<Vec<OpenClDeviceSummary>, String> {
        Err(OPENCL_DISABLED_MSG.to_string())
    }

    pub(crate) fn select_best_opencl_device(
        _devices: &[OpenClDeviceSummary],
    ) -> Option<OpenClDeviceSummary> {
        None
    }

    pub(crate) fn print_opencl_info() {
        println!("{}", OPENCL_DISABLED_MSG);
    }

    #[allow(dead_code)]
    pub(crate) fn opencl_hash_pubkey_batch() -> Result<(), String> {
        Err(OPENCL_DISABLED_MSG.to_string())
    }

    #[allow(dead_code)]
    pub(crate) fn opencl_filter_payload_batch() -> Result<(), String> {
        Err(OPENCL_DISABLED_MSG.to_string())
    }
}

pub(crate) use imp::{list_opencl_devices, print_opencl_info, select_best_opencl_device};
