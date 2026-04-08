#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use crate::memory_descriptor::UefiMemoryDescriptor;
use bootloader_api::info::FrameBufferInfo;
use bootloader_boot_config::BootConfig;
use bootloader_x86_64_common::{
    Kernel, RawFrameBufferInfo, SystemInfo, legacy_memory_region::LegacyFrameAllocator,
};
use core::{
    arch::x86_64::{__cpuid, _rdtsc},
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    slice,
};
use uefi::{
    CStr8, CStr16,
    prelude::{Boot, Handle, Status, SystemTable, entry},
    proto::{
        ProtocolPointer,
        console::gop::{GraphicsOutput, PixelFormat},
        device_path::DevicePath,
        loaded_image::LoadedImage,
        media::{
            file::{File, FileAttribute, FileInfo, FileMode},
            fs::SimpleFileSystem,
        },
        network::{
            IpAddress,
            pxe::{BaseCode, DhcpV4Packet},
        },
    },
    table::boot::{
        AllocateType, MemoryType, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol,
    },
};
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB},
};

mod direct_disk;
mod memory_descriptor;

static SYSTEM_TABLE: RacyCell<Option<SystemTable<Boot>>> = RacyCell::new(None);

struct RacyCell<T>(UnsafeCell<T>);

impl<T> RacyCell<T> {
    const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }
}

unsafe impl<T> Sync for RacyCell<T> {}

impl<T> core::ops::Deref for RacyCell<T> {
    type Target = UnsafeCell<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const PROFILE_STAGE_CAPACITY: usize = 16;

#[derive(Clone, Copy)]
struct StageRecord {
    label: &'static str,
    cycles: u64,
    since_boot_cycles: u64,
    bytes: Option<u64>,
}

struct StageProfiler {
    boot_start: u64,
    stage_start: u64,
    tsc_hz: Option<u64>,
    clock_logged: bool,
    records: [Option<StageRecord>; PROFILE_STAGE_CAPACITY],
    len: usize,
    flushed: usize,
}

impl StageProfiler {
    fn new(st: &SystemTable<Boot>) -> Self {
        let tsc_hz = estimate_tsc_hz().or_else(|| calibrate_tsc_hz(st));
        let now = read_tsc();
        Self {
            boot_start: now,
            stage_start: now,
            tsc_hz,
            clock_logged: false,
            records: [None; PROFILE_STAGE_CAPACITY],
            len: 0,
            flushed: 0,
        }
    }

    fn finish_stage(&mut self, label: &'static str) {
        self.finish_stage_with_bytes(label, None);
    }

    fn finish_stage_with_bytes(&mut self, label: &'static str, bytes: Option<usize>) {
        let now = read_tsc();
        let record = StageRecord {
            label,
            cycles: now.saturating_sub(self.stage_start),
            since_boot_cycles: now.saturating_sub(self.boot_start),
            bytes: bytes.and_then(|bytes| u64::try_from(bytes).ok()),
        };

        if self.len < self.records.len() {
            self.records[self.len] = Some(record);
            self.len += 1;
        }

        self.stage_start = now;
    }

    fn flush(&mut self) {
        if !self.clock_logged {
            match self.tsc_hz {
                Some(tsc_hz) => {
                    log::info!("profile: TSC frequency estimate {} MHz", tsc_hz / 1_000_000)
                }
                None => {
                    log::warn!("profile: TSC frequency estimate unavailable, reporting cycles only")
                }
            }
            self.clock_logged = true;
        }

        while self.flushed < self.len {
            let record = self.records[self.flushed].expect("profile record missing");
            self.log_record(record);
            self.flushed += 1;
        }
    }

    fn log_total(&self, label: &'static str) {
        let total_cycles = read_tsc().saturating_sub(self.boot_start);
        if let Some(tsc_hz) = self.tsc_hz {
            let total_micros = cycles_to_micros(total_cycles, tsc_hz);
            log::info!(
                "profile: {label} total={}.{:03} ms ({} cycles)",
                total_micros / 1000,
                total_micros % 1000,
                total_cycles
            );
        } else {
            log::info!("profile: {label} total={total_cycles} cycles");
        }
    }

    fn log_record(&self, record: StageRecord) {
        if let Some(tsc_hz) = self.tsc_hz {
            let stage_micros = cycles_to_micros(record.cycles, tsc_hz);
            let boot_micros = cycles_to_micros(record.since_boot_cycles, tsc_hz);
            match (
                record.bytes,
                bytes_per_second(record.bytes, record.cycles, tsc_hz),
            ) {
                (Some(bytes), Some(bytes_per_second)) => log::info!(
                    "profile: {} took {}.{:03} ms (boot {}.{:03} ms, {} bytes, {} MiB/s)",
                    record.label,
                    stage_micros / 1000,
                    stage_micros % 1000,
                    boot_micros / 1000,
                    boot_micros % 1000,
                    bytes,
                    bytes_per_second / (1024 * 1024)
                ),
                (Some(bytes), None) => log::info!(
                    "profile: {} took {}.{:03} ms (boot {}.{:03} ms, {} bytes)",
                    record.label,
                    stage_micros / 1000,
                    stage_micros % 1000,
                    boot_micros / 1000,
                    boot_micros % 1000,
                    bytes
                ),
                (None, _) => log::info!(
                    "profile: {} took {}.{:03} ms (boot {}.{:03} ms)",
                    record.label,
                    stage_micros / 1000,
                    stage_micros % 1000,
                    boot_micros / 1000,
                    boot_micros % 1000
                ),
            }
        } else if let Some(bytes) = record.bytes {
            log::info!(
                "profile: {} took {} cycles (boot {} cycles, {} bytes)",
                record.label,
                record.cycles,
                record.since_boot_cycles,
                bytes
            );
        } else {
            log::info!(
                "profile: {} took {} cycles (boot {} cycles)",
                record.label,
                record.cycles,
                record.since_boot_cycles
            );
        }
    }
}

fn read_tsc() -> u64 {
    unsafe { _rdtsc() }
}

fn estimate_tsc_hz() -> Option<u64> {
    let max_basic_leaf = __cpuid(0).eax;

    if max_basic_leaf >= 0x15 {
        let leaf = __cpuid(0x15);
        if leaf.eax != 0 && leaf.ebx != 0 && leaf.ecx != 0 {
            return Some(
                u64::from(leaf.ecx)
                    .checked_mul(u64::from(leaf.ebx))?
                    .checked_div(u64::from(leaf.eax))?,
            );
        }
    }

    if max_basic_leaf >= 0x16 {
        let leaf = __cpuid(0x16);
        if leaf.eax != 0 {
            return Some(u64::from(leaf.eax) * 1_000_000);
        }
    }

    None
}

fn calibrate_tsc_hz(st: &SystemTable<Boot>) -> Option<u64> {
    const CALIBRATION_DELAY_US: usize = 10_000;

    let start = read_tsc();
    st.boot_services().stall(CALIBRATION_DELAY_US);
    let end = read_tsc();
    let cycles = end.checked_sub(start)?;
    if cycles == 0 {
        return None;
    }

    Some(((u128::from(cycles) * 1_000_000) / CALIBRATION_DELAY_US as u128) as u64)
}

fn cycles_to_micros(cycles: u64, tsc_hz: u64) -> u64 {
    ((u128::from(cycles) * 1_000_000) / u128::from(tsc_hz)) as u64
}

fn bytes_per_second(bytes: Option<u64>, cycles: u64, tsc_hz: u64) -> Option<u64> {
    let bytes = bytes?;
    if cycles == 0 {
        return None;
    }

    Some(((u128::from(bytes) * u128::from(tsc_hz)) / u128::from(cycles)) as u64)
}

struct LoadedRamdisk {
    bytes: &'static mut [u8],
    source: RamdiskSource,
}

#[derive(Clone, Copy, Debug)]
enum RamdiskSource {
    DirectDisk,
    UefiFile,
    Tftp,
}

#[entry]
fn efi_main(image: Handle, st: SystemTable<Boot>) -> Status {
    main_inner(image, st)
}

fn main_inner(image: Handle, mut st: SystemTable<Boot>) -> Status {
    // temporarily clone the y table for printing panics
    unsafe {
        *SYSTEM_TABLE.get() = Some(st.unsafe_clone());
    }

    let mut profiler = StageProfiler::new(&st);
    let mut boot_mode = BootMode::Disk;

    let mut kernel = load_kernel(image, &mut st, boot_mode);
    profiler.finish_stage_with_bytes("load_kernel_disk", kernel.as_ref().map(|(_, len)| *len));
    if kernel.is_none() {
        // Try TFTP boot
        boot_mode = BootMode::Tftp;
        kernel = load_kernel(image, &mut st, boot_mode);
        profiler.finish_stage_with_bytes("load_kernel_tftp", kernel.as_ref().map(|(_, len)| *len));
    }
    let (kernel, _) = kernel.expect("Failed to load kernel");

    let config_file = load_config_file(image, &mut st, boot_mode);
    profiler.finish_stage_with_bytes(
        match boot_mode {
            BootMode::Disk => "load_config_disk",
            BootMode::Tftp => "load_config_tftp",
        },
        config_file.as_ref().map(|config_file| config_file.len()),
    );
    let mut error_loading_config: Option<serde_json_core::de::Error> = None;
    let mut config: BootConfig = match config_file
        .as_deref()
        .map(serde_json_core::from_slice)
        .transpose()
    {
        Ok(data) => data.unwrap_or_default().0,
        Err(err) => {
            error_loading_config = Some(err);
            Default::default()
        }
    };
    profiler.finish_stage("parse_config");

    #[allow(deprecated)]
    if config.frame_buffer.minimum_framebuffer_height.is_none() {
        config.frame_buffer.minimum_framebuffer_height =
            kernel.config.frame_buffer.minimum_framebuffer_height;
    }
    #[allow(deprecated)]
    if config.frame_buffer.minimum_framebuffer_width.is_none() {
        config.frame_buffer.minimum_framebuffer_width =
            kernel.config.frame_buffer.minimum_framebuffer_width;
    }
    let framebuffer = init_logger(image, &st, &config);
    profiler.finish_stage("init_logger");

    unsafe {
        *SYSTEM_TABLE.get() = None;
    }

    log::info!("UEFI bootloader started");
    profiler.flush();

    if let Some(framebuffer) = framebuffer {
        log::info!("Using framebuffer at {:#x}", framebuffer.addr);
    }

    if let Some(err) = error_loading_config {
        log::warn!("Failed to deserialize the config file {:?}", err);
    } else {
        log::info!("Reading configuration from disk was successful");
    }

    log::info!("Trying to load ramdisk via {:?}", boot_mode);
    // Ramdisk must load from same source, or not at all.
    let ramdisk = load_ramdisk(image, &mut st, boot_mode);
    profiler.finish_stage_with_bytes(
        match boot_mode {
            BootMode::Disk => "load_ramdisk_disk",
            BootMode::Tftp => "load_ramdisk_tftp",
        },
        ramdisk.as_ref().map(|ramdisk| ramdisk.bytes.len()),
    );
    profiler.flush();

    match ramdisk.as_ref() {
        Some(ramdisk) => log::info!(
            "Loaded ramdisk via {:?} ({} bytes)",
            ramdisk.source,
            ramdisk.bytes.len()
        ),
        None => log::info!("Ramdisk not found."),
    }

    log::trace!("exiting boot services");
    let (system_table, mut memory_map) = st.exit_boot_services();
    profiler.finish_stage("exit_boot_services");
    profiler.flush();

    memory_map.sort();
    profiler.finish_stage("sort_memory_map");
    profiler.flush();

    let mut frame_allocator =
        LegacyFrameAllocator::new(memory_map.entries().copied().map(UefiMemoryDescriptor));
    profiler.finish_stage("init_frame_allocator");
    profiler.flush();

    let max_phys_addr = frame_allocator.max_phys_addr();
    let page_tables = create_page_tables(&mut frame_allocator, max_phys_addr, framebuffer.as_ref());
    profiler.finish_stage("create_page_tables");
    profiler.flush();

    let mut ramdisk_len = 0u64;
    let ramdisk_addr = if let Some(rd) = ramdisk {
        ramdisk_len = rd.bytes.len() as u64;
        Some(rd.bytes.as_ptr() as usize as u64)
    } else {
        None
    };
    let system_info = SystemInfo {
        framebuffer,
        rsdp_addr: {
            use uefi::table::cfg;
            let mut config_entries = system_table.config_table().iter();
            // look for an ACPI2 RSDP first
            let acpi2_rsdp = config_entries.find(|entry| matches!(entry.guid, cfg::ACPI2_GUID));
            // if no ACPI2 RSDP is found, look for a ACPI1 RSDP
            let rsdp = acpi2_rsdp
                .or_else(|| config_entries.find(|entry| matches!(entry.guid, cfg::ACPI_GUID)));
            rsdp.map(|entry| PhysAddr::new(entry.address as u64))
        },
        ramdisk_addr,
        ramdisk_len,
    };
    profiler.finish_stage("build_system_info");
    profiler.flush();
    profiler.log_total("boot_to_kernel");

    bootloader_x86_64_common::load_and_switch_to_kernel(
        kernel,
        config,
        frame_allocator,
        page_tables,
        system_info,
    );
}

#[derive(Clone, Copy, Debug)]
pub enum BootMode {
    Disk,
    Tftp,
}

fn load_ramdisk(
    image: Handle,
    st: &mut SystemTable<Boot>,
    boot_mode: BootMode,
) -> Option<LoadedRamdisk> {
    match boot_mode {
        BootMode::Disk => direct_disk::load_root_file(image, st, "ramdisk")
            .map(|bytes| LoadedRamdisk {
                bytes,
                source: RamdiskSource::DirectDisk,
            })
            .or_else(|| {
                load_file_from_disk("ramdisk\0", image, st).map(|bytes| LoadedRamdisk {
                    bytes,
                    source: RamdiskSource::UefiFile,
                })
            }),
        BootMode::Tftp => {
            load_file_from_tftp_boot_server("ramdisk\0", image, st).map(|bytes| LoadedRamdisk {
                bytes,
                source: RamdiskSource::Tftp,
            })
        }
    }
}

fn load_config_file(
    image: Handle,
    st: &mut SystemTable<Boot>,
    boot_mode: BootMode,
) -> Option<&'static mut [u8]> {
    load_file_from_boot_method(image, st, "boot.json\0", boot_mode)
}

fn load_kernel(
    image: Handle,
    st: &mut SystemTable<Boot>,
    boot_mode: BootMode,
) -> Option<(Kernel<'static>, usize)> {
    let kernel_slice = load_file_from_boot_method(image, st, "kernel-x86_64\0", boot_mode)?;
    let kernel_len = kernel_slice.len();
    Some((Kernel::parse(kernel_slice), kernel_len))
}

fn load_file_from_boot_method(
    image: Handle,
    st: &mut SystemTable<Boot>,
    filename: &str,
    boot_mode: BootMode,
) -> Option<&'static mut [u8]> {
    match boot_mode {
        BootMode::Disk => load_file_from_disk(filename, image, st),
        BootMode::Tftp => load_file_from_tftp_boot_server(filename, image, st),
    }
}

fn open_device_path_protocol(
    image: Handle,
    st: &SystemTable<Boot>,
) -> Option<ScopedProtocol<'_, DevicePath>> {
    let this = st.boot_services();
    let loaded_image = unsafe {
        this.open_protocol::<LoadedImage>(
            OpenProtocolParams {
                handle: image,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::Exclusive,
        )
    };

    if loaded_image.is_err() {
        log::error!("Failed to open protocol LoadedImage");
        return None;
    }
    let loaded_image = loaded_image.unwrap();
    let loaded_image = loaded_image.deref();

    let device_handle = loaded_image.device();

    let device_path = unsafe {
        this.open_protocol::<DevicePath>(
            OpenProtocolParams {
                handle: device_handle,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::Exclusive,
        )
    };
    if device_path.is_err() {
        log::error!("Failed to open protocol DevicePath");
        return None;
    }
    Some(device_path.unwrap())
}

fn locate_and_open_protocol<P: ProtocolPointer>(
    image: Handle,
    st: &SystemTable<Boot>,
) -> Option<ScopedProtocol<'_, P>> {
    let this = st.boot_services();
    let device_path = open_device_path_protocol(image, st)?;
    let mut device_path = device_path.deref();

    let fs_handle = this.locate_device_path::<P>(&mut device_path);
    if fs_handle.is_err() {
        log::error!("Failed to open device path");
        return None;
    }

    let fs_handle = fs_handle.unwrap();

    let opened_handle = unsafe {
        this.open_protocol::<P>(
            OpenProtocolParams {
                handle: fs_handle,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::Exclusive,
        )
    };

    if opened_handle.is_err() {
        log::error!("Failed to open protocol {}", core::any::type_name::<P>());
        return None;
    }
    Some(opened_handle.unwrap())
}

fn load_file_from_disk(
    name: &str,
    image: Handle,
    st: &SystemTable<Boot>,
) -> Option<&'static mut [u8]> {
    const DISK_READ_CHUNK_SIZE: usize = 8 * 1024 * 1024;

    let mut file_system_raw = locate_and_open_protocol::<SimpleFileSystem>(image, st)?;
    let file_system = file_system_raw.deref_mut();

    let mut root = file_system.open_volume().unwrap();
    let mut buf = [0u16; 256];
    assert!(name.len() < 256);
    let filename = CStr16::from_str_with_buf(name.trim_end_matches('\0'), &mut buf)
        .expect("Failed to convert string to utf16");

    let file_handle_result = root.open(filename, FileMode::Read, FileAttribute::empty());

    let file_handle = file_handle_result.ok()?;

    let mut file = match file_handle.into_type().unwrap() {
        uefi::proto::media::file::FileType::Regular(f) => f,
        uefi::proto::media::file::FileType::Dir(_) => panic!(),
    };

    let mut buf = [0; 500];
    let file_info: &mut FileInfo = file.get_info(&mut buf).unwrap();
    let file_size = usize::try_from(file_info.file_size()).unwrap();

    let file_ptr = st
        .boot_services()
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            ((file_size - 1) / 4096) + 1,
        )
        .unwrap() as *mut u8;
    let file_slice = unsafe { slice::from_raw_parts_mut(file_ptr, file_size) };

    let mut bytes_read = 0;
    while bytes_read < file_slice.len() {
        let chunk_end = usize::min(bytes_read + DISK_READ_CHUNK_SIZE, file_slice.len());
        let read = file.read(&mut file_slice[bytes_read..chunk_end]).unwrap();
        assert_ne!(read, 0, "Unexpected EOF while reading `{name}`");
        bytes_read += read;
    }

    Some(file_slice)
}

/// Try to load a kernel from a TFTP boot server.
fn load_file_from_tftp_boot_server(
    name: &str,
    image: Handle,
    st: &SystemTable<Boot>,
) -> Option<&'static mut [u8]> {
    let mut base_code_raw = locate_and_open_protocol::<BaseCode>(image, st)?;
    let base_code = base_code_raw.deref_mut();

    // Find the TFTP boot server.
    let mode = base_code.mode();
    assert!(mode.dhcp_ack_received);
    let dhcpv4: &DhcpV4Packet = mode.dhcp_ack.as_ref();
    let server_ip = IpAddress::new_v4(dhcpv4.bootp_si_addr);
    assert!(name.len() < 256);

    let filename = CStr8::from_bytes_with_nul(name.as_bytes()).unwrap();

    // Determine the kernel file size.
    let file_size = base_code.tftp_get_file_size(&server_ip, filename).ok()?;
    let kernel_size = usize::try_from(file_size).expect("The file size should fit into usize");

    // Allocate some memory for the kernel file.
    let ptr = st
        .boot_services()
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            ((kernel_size - 1) / 4096) + 1,
        )
        .expect("Failed to allocate memory for the file") as *mut u8;
    let slice = unsafe { slice::from_raw_parts_mut(ptr, kernel_size) };

    // Load the kernel file.
    base_code
        .tftp_read_file(&server_ip, filename, Some(slice))
        .expect("Failed to read kernel file from the TFTP boot server");

    Some(slice)
}

/// Creates page table abstraction types for both the bootloader and kernel page tables.
fn create_page_tables(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    max_phys_addr: PhysAddr,
    frame_buffer: Option<&RawFrameBufferInfo>,
) -> bootloader_x86_64_common::PageTables {
    // UEFI identity-maps all memory, so the offset between physical and virtual addresses is 0
    let phys_offset = VirtAddr::new(0);

    // copy the currently active level 4 page table, because it might be read-only
    log::trace!("switching to new level 4 table");
    let bootloader_page_table = {
        let old_table = {
            let frame = x86_64::registers::control::Cr3::read().0;
            let ptr: *const PageTable = (phys_offset + frame.start_address().as_u64()).as_ptr();
            unsafe { &*ptr }
        };
        let new_frame = frame_allocator
            .allocate_frame()
            .expect("Failed to allocate frame for new level 4 table");
        let new_table: &mut PageTable = {
            let ptr: *mut PageTable =
                (phys_offset + new_frame.start_address().as_u64()).as_mut_ptr();
            // create a new, empty page table
            unsafe {
                ptr.write(PageTable::new());
                &mut *ptr
            }
        };

        // copy the pml4 entries for all identity mapped memory.
        let end_addr = VirtAddr::new(max_phys_addr.as_u64() - 1);
        for p4 in 0..=usize::from(end_addr.p4_index()) {
            new_table[p4] = old_table[p4].clone();
        }

        // copy the pml4 entry for the frame buffer (the frame buffer is not
        // necessarily part of the identity mapping).
        if let Some(frame_buffer) = frame_buffer {
            let start_addr = VirtAddr::new(frame_buffer.addr.as_u64());
            let end_addr = start_addr + frame_buffer.info.byte_len as u64;
            for p4 in usize::from(start_addr.p4_index())..=usize::from(end_addr.p4_index()) {
                new_table[p4] = old_table[p4].clone();
            }
        }

        // the first level 4 table entry is now identical, so we can just load the new one
        unsafe {
            x86_64::registers::control::Cr3::write(
                new_frame,
                x86_64::registers::control::Cr3Flags::empty(),
            );
            OffsetPageTable::new(&mut *new_table, phys_offset)
        }
    };

    // create a new page table hierarchy for the kernel
    let (kernel_page_table, kernel_level_4_frame) = {
        // get an unused frame for new level 4 page table
        let frame: PhysFrame = frame_allocator.allocate_frame().expect("no unused frames");
        log::info!("New page table at: {:#?}", &frame);
        // get the corresponding virtual address
        let addr = phys_offset + frame.start_address().as_u64();
        // initialize a new page table
        let ptr = addr.as_mut_ptr();
        unsafe { *ptr = PageTable::new() };
        let level_4_table = unsafe { &mut *ptr };
        (
            unsafe { OffsetPageTable::new(level_4_table, phys_offset) },
            frame,
        )
    };

    bootloader_x86_64_common::PageTables {
        bootloader: bootloader_page_table,
        kernel: kernel_page_table,
        kernel_level_4_frame,
    }
}

fn init_logger(
    image_handle: Handle,
    st: &SystemTable<Boot>,
    config: &BootConfig,
) -> Option<RawFrameBufferInfo> {
    let gop_handle = st
        .boot_services()
        .get_handle_for_protocol::<GraphicsOutput>()
        .ok()?;
    let mut gop = unsafe {
        st.boot_services()
            .open_protocol::<GraphicsOutput>(
                OpenProtocolParams {
                    handle: gop_handle,
                    agent: image_handle,
                    controller: None,
                },
                OpenProtocolAttributes::Exclusive,
            )
            .ok()?
    };

    let mode = {
        let modes = gop.modes();
        match (
            config
                .frame_buffer
                .minimum_framebuffer_height
                .map(|v| usize::try_from(v).unwrap()),
            config
                .frame_buffer
                .minimum_framebuffer_width
                .map(|v| usize::try_from(v).unwrap()),
        ) {
            (Some(height), Some(width)) => modes
                .filter(|m| {
                    let res = m.info().resolution();
                    res.1 >= height && res.0 >= width
                })
                .last(),
            (Some(height), None) => modes.filter(|m| m.info().resolution().1 >= height).last(),
            (None, Some(width)) => modes.filter(|m| m.info().resolution().0 >= width).last(),
            _ => None,
        }
    };
    if let Some(mode) = mode {
        gop.set_mode(&mode)
            .expect("Failed to apply the desired display mode");
    }

    let mode_info = gop.current_mode_info();
    let mut framebuffer = gop.frame_buffer();
    let slice = unsafe { slice::from_raw_parts_mut(framebuffer.as_mut_ptr(), framebuffer.size()) };
    let info = FrameBufferInfo {
        byte_len: framebuffer.size(),
        width: mode_info.resolution().0,
        height: mode_info.resolution().1,
        pixel_format: match mode_info.pixel_format() {
            PixelFormat::Rgb => bootloader_api::info::PixelFormat::Rgb,
            PixelFormat::Bgr => bootloader_api::info::PixelFormat::Bgr,
            PixelFormat::Bitmask | PixelFormat::BltOnly => {
                panic!("Bitmask and BltOnly framebuffers are not supported")
            }
        },
        bytes_per_pixel: 4,
        stride: mode_info.stride(),
    };

    bootloader_x86_64_common::init_logger(
        slice,
        info,
        config.log_level,
        config.frame_buffer_logging,
        config.serial_logging,
    );

    Some(RawFrameBufferInfo {
        addr: PhysAddr::new(framebuffer.as_mut_ptr() as u64),
        info,
    })
}

#[cfg(target_os = "uefi")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::arch::asm;
    use core::fmt::Write;

    if let Some(st) = unsafe { &mut *SYSTEM_TABLE.get() } {
        let _ = st.stdout().clear();
        let _ = writeln!(st.stdout(), "{}", info);
    }

    unsafe {
        bootloader_x86_64_common::logger::LOGGER
            .get()
            .map(|l| l.force_unlock())
    };
    log::error!("{}", info);

    loop {
        unsafe { asm!("cli; hlt") };
    }
}
