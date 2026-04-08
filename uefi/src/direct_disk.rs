use core::{cmp, ops::Deref, ptr::NonNull, slice};
use uefi::{
    Handle,
    prelude::{Boot, SystemTable},
    proto::{
        ProtocolPointer,
        device_path::DevicePath,
        loaded_image::LoadedImage,
        media::block::{BlockIO, BlockIOMedia},
    },
    table::boot::{
        AllocateType, MemoryType, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol,
    },
};

const DIRECTORY_ENTRY_BYTES: usize = 32;
const UNUSED_ENTRY_PREFIX: u8 = 0xE5;
const END_OF_DIRECTORY_PREFIX: u8 = 0;
const LONG_NAME_ENTRY_ORDER_LAST: u8 = 0x40;
const LONG_NAME_ENTRY_ORDER_MASK: u8 = 0x1F;
const LONG_NAME_CHARS_PER_ENTRY: usize = 13;
const MAX_LONG_NAME_LEN: usize = 260;
const DEFAULT_CACHE_BLOCKS: usize = 64;
const MAX_CACHE_BLOCKS: usize = 512;
const DIRECT_READ_TARGET_BYTES: usize = 8 * 1024 * 1024;
const PAGE_SIZE: usize = 4096;

pub fn load_root_file(
    image: Handle,
    st: &SystemTable<Boot>,
    name: &str,
) -> Option<&'static mut [u8]> {
    match try_load_root_file(image, st, name) {
        Ok(file) => file,
        Err(()) => {
            log::warn!("Direct disk load for `{name}` failed, falling back to UEFI file protocol");
            None
        }
    }
}

fn try_load_root_file(
    image: Handle,
    st: &SystemTable<Boot>,
    name: &str,
) -> Result<Option<&'static mut [u8]>, ()> {
    let mut fs = DirectFatFs::new(image, st).ok_or(())?;
    let file = match fs.find_root_file(name)? {
        Some(file) => file,
        None => return Ok(None),
    };

    let file_len = usize::try_from(file.file_size).map_err(|_| ())?;
    let file_slice = allocate_loader_data_aligned(st, file_len, fs.required_alignment());
    let stats = fs.read_file(&file, file_slice)?;
    log::info!(
        "Direct disk load `{name}`: {} bytes in {} extent(s), block_size={} io_align={} cache={} KiB direct_chunk={} KiB",
        file_len,
        stats.extents,
        fs.reader.block_size,
        fs.reader.io_align,
        fs.reader.cache.len() / 1024,
        fs.reader
            .max_direct_blocks
            .saturating_mul(fs.reader.block_size)
            / 1024
    );
    Ok(Some(file_slice))
}

fn allocate_loader_data_aligned(
    st: &SystemTable<Boot>,
    len: usize,
    align: usize,
) -> &'static mut [u8] {
    if len == 0 {
        return unsafe { slice::from_raw_parts_mut(NonNull::<u8>::dangling().as_ptr(), 0) };
    }

    let align = align.max(PAGE_SIZE);
    let alloc_len = len
        .checked_add(align.saturating_sub(1))
        .expect("loader allocation overflow");
    let ptr = st
        .boot_services()
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            alloc_len.div_ceil(PAGE_SIZE),
        )
        .unwrap() as usize;
    let aligned_ptr = align_up(ptr, align).expect("failed to align loader allocation");
    unsafe { slice::from_raw_parts_mut(aligned_ptr as *mut u8, len) }
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    if align <= 1 {
        return Some(value);
    }

    let remainder = value % align;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(align - remainder)
    }
}

struct DirectFatFs<'a> {
    reader: BlockReader<'a>,
    bpb: Bpb,
    fat: &'static [u8],
}

impl<'a> DirectFatFs<'a> {
    fn new(image: Handle, st: &'a SystemTable<Boot>) -> Option<Self> {
        let mut reader = BlockReader::new(image, st)?;
        let bpb = Bpb::parse(&mut reader)?;
        let fat_slice =
            allocate_loader_data_aligned(st, bpb.fat_size_bytes(), reader.required_alignment());
        reader.read_exact(bpb.fat_offset(), fat_slice).ok()?;

        Some(Self {
            reader,
            bpb,
            fat: fat_slice,
        })
    }

    fn required_alignment(&self) -> usize {
        self.reader.required_alignment()
    }

    fn find_root_file(&mut self, target_name: &str) -> Result<Option<File>, ()> {
        let mut long_name = LongName::new();
        match self.bpb.fat_type() {
            FatType::Fat12 | FatType::Fat16 => {
                let root_start = self.bpb.root_directory_offset();
                let root_end = root_start + self.bpb.root_directory_size() as u64;
                let mut offset = root_start;
                while offset < root_end {
                    let entry = self.read_dir_entry(offset)?;
                    if let Some(file) =
                        self.process_root_entry(entry, target_name, &mut long_name)?
                    {
                        return Ok(Some(file));
                    }
                    if entry[0] == END_OF_DIRECTORY_PREFIX {
                        return Ok(None);
                    }
                    offset += DIRECTORY_ENTRY_BYTES as u64;
                }
                Ok(None)
            }
            FatType::Fat32 => {
                let mut current_cluster = self.bpb.root_cluster;
                loop {
                    let cluster = self.cluster_from_entry(current_cluster)?;
                    let mut offset = cluster.start_offset;
                    let cluster_end = offset + u64::from(cluster.len_bytes);
                    while offset < cluster_end {
                        let entry = self.read_dir_entry(offset)?;
                        if let Some(file) =
                            self.process_root_entry(entry, target_name, &mut long_name)?
                        {
                            return Ok(Some(file));
                        }
                        if entry[0] == END_OF_DIRECTORY_PREFIX {
                            return Ok(None);
                        }
                        offset += DIRECTORY_ENTRY_BYTES as u64;
                    }

                    match self.next_cluster(cluster.index)? {
                        Some(next) => current_cluster = next,
                        None => return Ok(None),
                    }
                }
            }
        }
    }

    fn process_root_entry(
        &self,
        entry: [u8; DIRECTORY_ENTRY_BYTES],
        target_name: &str,
        long_name: &mut LongName,
    ) -> Result<Option<File>, ()> {
        if entry[0] == UNUSED_ENTRY_PREFIX {
            long_name.clear();
            return Ok(None);
        }

        let attributes = entry[11];
        if attributes == directory_attributes::LONG_NAME {
            long_name.push(entry);
            return Ok(None);
        }

        let file = parse_file_entry(entry)?;
        let matches_long_name = long_name.matches_ascii(target_name);
        long_name.clear();

        if file.attributes & directory_attributes::DIRECTORY != 0
            || file.attributes & directory_attributes::VOLUME_ID != 0
        {
            return Ok(None);
        }

        if matches_long_name || short_name_matches(&entry, target_name) {
            Ok(Some(file))
        } else {
            Ok(None)
        }
    }

    fn read_file(&mut self, file: &File, out: &mut [u8]) -> Result<FileReadStats, ()> {
        if out.is_empty() {
            return Ok(FileReadStats { extents: 0 });
        }

        let bytes_per_cluster = usize::try_from(self.bpb.bytes_per_cluster()).map_err(|_| ())?;
        let mut current_cluster = file.first_cluster;
        let mut written = 0usize;
        let mut extents = 0usize;

        while written < out.len() {
            let cluster = self.cluster_from_entry(current_cluster)?;
            let mut extent_clusters = 1usize;
            let mut last_cluster = cluster.index;
            let mut next_cluster = self.next_cluster(last_cluster)?;

            while let Some(next) = next_cluster {
                if next != last_cluster + 1 {
                    break;
                }
                extent_clusters += 1;
                last_cluster = next;
                if extent_clusters.checked_mul(bytes_per_cluster).ok_or(())? >= out.len() - written
                {
                    next_cluster = self.next_cluster(last_cluster)?;
                    break;
                }
                next_cluster = self.next_cluster(last_cluster)?;
            }

            let extent_len = cmp::min(
                extent_clusters.checked_mul(bytes_per_cluster).ok_or(())?,
                out.len() - written,
            );
            self.reader.read_exact(
                cluster.start_offset,
                &mut out[written..written + extent_len],
            )?;
            extents += 1;
            written += extent_len;

            if written == out.len() {
                break;
            }

            current_cluster = next_cluster.ok_or(())?;
        }

        if written == out.len() {
            Ok(FileReadStats { extents })
        } else {
            Err(())
        }
    }

    fn read_dir_entry(&mut self, offset: u64) -> Result<[u8; DIRECTORY_ENTRY_BYTES], ()> {
        let mut entry = [0u8; DIRECTORY_ENTRY_BYTES];
        self.reader.read_exact(offset, &mut entry)?;
        Ok(entry)
    }

    fn cluster_from_entry(&self, entry: u32) -> Result<Cluster, ()> {
        let cluster =
            match classify_fat_entry(self.bpb.fat_type(), entry, self.bpb.maximum_valid_cluster())
                .map_err(|_| ())?
            {
                FileFatEntry::AllocatedCluster(cluster) => cluster,
                FileFatEntry::EndOfFile => return Err(()),
            };

        Ok(Cluster {
            index: cluster,
            start_offset: self.bpb.cluster_offset(cluster),
            len_bytes: self.bpb.bytes_per_cluster(),
        })
    }

    fn next_cluster(&self, cluster: u32) -> Result<Option<u32>, ()> {
        let next = fat_entry_of_nth_cluster(self.fat, self.bpb.fat_type(), cluster).ok_or(())?;
        match classify_fat_entry(self.bpb.fat_type(), next, self.bpb.maximum_valid_cluster())
            .map_err(|_| ())?
        {
            FileFatEntry::AllocatedCluster(cluster) => Ok(Some(cluster)),
            FileFatEntry::EndOfFile => Ok(None),
        }
    }
}

struct BlockReader<'a> {
    block: ScopedProtocol<'a, BlockIO>,
    media_id: u32,
    block_size: usize,
    io_align: usize,
    cache_blocks: usize,
    optimal_transfer_blocks: usize,
    max_direct_blocks: usize,
    last_block_plus_one: u64,
    cache: &'static mut [u8],
    cached_lba: Option<u64>,
    cached_len_bytes: usize,
}

impl<'a> BlockReader<'a> {
    fn new(image: Handle, st: &'a SystemTable<Boot>) -> Option<Self> {
        let block = open_boot_device_protocol::<BlockIO>(image, st)?;
        let (
            media_id,
            block_size,
            io_align,
            cache_blocks,
            optimal_transfer_blocks,
            max_direct_blocks,
            last_block_plus_one,
        ) = {
            let media = block.media();
            let block_size = usize::try_from(media.block_size()).ok()?;
            if block_size == 0 {
                return None;
            }

            let io_align = match usize::try_from(media.io_align()).ok()? {
                0 | 1 => 1,
                align => align,
            };
            let optimal_transfer_blocks = optimal_transfer_blocks(media);

            (
                media.media_id(),
                block_size,
                io_align,
                cache_blocks(optimal_transfer_blocks),
                optimal_transfer_blocks,
                max_direct_blocks(block_size, optimal_transfer_blocks),
                media.last_block().checked_add(1)?,
            )
        };

        let cache_len = block_size.checked_mul(cache_blocks)?;
        let cache = allocate_loader_data_aligned(st, cache_len, io_align.max(PAGE_SIZE));

        Some(Self {
            block,
            media_id,
            block_size,
            io_align,
            cache_blocks,
            optimal_transfer_blocks,
            max_direct_blocks,
            last_block_plus_one,
            cache,
            cached_lba: None,
            cached_len_bytes: 0,
        })
    }

    fn required_alignment(&self) -> usize {
        self.io_align.max(PAGE_SIZE)
    }

    fn read_exact(&mut self, mut offset: u64, mut buffer: &mut [u8]) -> Result<(), ()> {
        while !buffer.is_empty() {
            if let Some(direct_len) = self.direct_read_len(offset, buffer)? {
                let (direct, rest) = buffer.split_at_mut(direct_len);
                self.block
                    .read_blocks(self.media_id, offset / self.block_size_u64(), direct)
                    .map_err(|_| ())?;
                offset += u64::try_from(direct_len).map_err(|_| ())?;
                buffer = rest;
                continue;
            }

            self.populate_cache(offset)?;

            let cached_lba = self.cached_lba.ok_or(())?;
            let cached_start = cached_lba.checked_mul(self.block_size_u64()).ok_or(())?;
            let within_cache =
                usize::try_from(offset.checked_sub(cached_start).ok_or(())?).map_err(|_| ())?;
            if within_cache >= self.cached_len_bytes {
                return Err(());
            }

            let copy_len = cmp::min(buffer.len(), self.cached_len_bytes - within_cache);
            let (chunk, rest) = buffer.split_at_mut(copy_len);
            chunk.copy_from_slice(&self.cache[within_cache..within_cache + copy_len]);
            offset += u64::try_from(copy_len).map_err(|_| ())?;
            buffer = rest;
        }

        Ok(())
    }

    fn direct_read_len(&self, offset: u64, buffer: &mut [u8]) -> Result<Option<usize>, ()> {
        if buffer.len() < self.block_size || offset % self.block_size_u64() != 0 {
            return Ok(None);
        }

        if self.io_align > 1 && (buffer.as_mut_ptr() as usize) % self.io_align != 0 {
            return Ok(None);
        }

        let lba = offset / self.block_size_u64();
        let remaining_blocks = self.last_block_plus_one.checked_sub(lba).ok_or(())?;
        let remaining_blocks = usize::try_from(remaining_blocks).unwrap_or(usize::MAX);
        if remaining_blocks == 0 {
            return Ok(None);
        }

        let whole_blocks = buffer.len() / self.block_size;
        let mut read_blocks = cmp::min(
            cmp::min(whole_blocks, self.max_direct_blocks),
            remaining_blocks,
        );
        if read_blocks < whole_blocks {
            let align_blocks = lcm(
                self.required_direct_block_multiple(),
                self.optimal_transfer_blocks,
            );
            if align_blocks > 1 {
                read_blocks -= read_blocks % align_blocks;
            }
        }
        if read_blocks == 0 {
            Ok(None)
        } else {
            Ok(Some(read_blocks * self.block_size))
        }
    }

    fn populate_cache(&mut self, offset: u64) -> Result<(), ()> {
        let target_lba = offset / self.block_size_u64();
        if let Some(cached_lba) = self.cached_lba {
            let cached_start = cached_lba.checked_mul(self.block_size_u64()).ok_or(())?;
            let cached_end = cached_start
                .checked_add(u64::try_from(self.cached_len_bytes).map_err(|_| ())?)
                .ok_or(())?;
            if offset >= cached_start && offset < cached_end {
                return Ok(());
            }
        }

        let cache_blocks = u64::try_from(self.cache_blocks).map_err(|_| ())?;
        let window_lba = (target_lba / cache_blocks)
            .checked_mul(cache_blocks)
            .ok_or(())?;
        let remaining_blocks = self.last_block_plus_one.checked_sub(window_lba).ok_or(())?;
        let blocks_to_read = cmp::min(remaining_blocks, cache_blocks);
        if blocks_to_read == 0 {
            return Err(());
        }

        let byte_len = usize::try_from(blocks_to_read)
            .map_err(|_| ())?
            .checked_mul(self.block_size)
            .ok_or(())?;

        self.block
            .read_blocks(self.media_id, window_lba, &mut self.cache[..byte_len])
            .map_err(|_| ())?;
        self.cached_lba = Some(window_lba);
        self.cached_len_bytes = byte_len;
        Ok(())
    }

    fn block_size_u64(&self) -> u64 {
        self.block_size as u64
    }

    fn required_direct_block_multiple(&self) -> usize {
        self.io_align.max(self.block_size).div_ceil(self.block_size)
    }
}

fn optimal_transfer_blocks(media: &BlockIOMedia) -> usize {
    let granularity = usize::try_from(media.optimal_transfer_length_granularity()).unwrap_or(0);
    if granularity == 0 { 1 } else { granularity }
}

fn cache_blocks(optimal_transfer_blocks: usize) -> usize {
    if optimal_transfer_blocks == 1 {
        DEFAULT_CACHE_BLOCKS
    } else {
        optimal_transfer_blocks.min(MAX_CACHE_BLOCKS)
    }
}

fn max_direct_blocks(block_size: usize, optimal_transfer_blocks: usize) -> usize {
    let target_blocks = DIRECT_READ_TARGET_BYTES.div_ceil(block_size);
    round_up(
        target_blocks.max(optimal_transfer_blocks),
        optimal_transfer_blocks,
    )
}

fn round_up(value: usize, multiple: usize) -> usize {
    if multiple <= 1 {
        value
    } else {
        value.div_ceil(multiple) * multiple
    }
}

fn lcm(left: usize, right: usize) -> usize {
    left / gcd(left, right) * right
}

fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

fn open_boot_device_protocol<P: ProtocolPointer + ?Sized>(
    image: Handle,
    st: &SystemTable<Boot>,
) -> Option<ScopedProtocol<'_, P>> {
    let boot_services = st.boot_services();

    let loaded_image = unsafe {
        boot_services
            .open_protocol::<LoadedImage>(
                OpenProtocolParams {
                    handle: image,
                    agent: image,
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
            .ok()?
    };
    let device_handle = loaded_image.device();

    let device_path = unsafe {
        boot_services
            .open_protocol::<DevicePath>(
                OpenProtocolParams {
                    handle: device_handle,
                    agent: image,
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
            .ok()?
    };
    let mut device_path = device_path.deref();

    let protocol_handle = boot_services
        .locate_device_path::<P>(&mut device_path)
        .ok()?;
    unsafe {
        boot_services
            .open_protocol::<P>(
                OpenProtocolParams {
                    handle: protocol_handle,
                    agent: image,
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
            .ok()
    }
}

#[derive(Clone, Copy)]
struct File {
    first_cluster: u32,
    file_size: u32,
    attributes: u8,
}

#[derive(Clone, Copy)]
struct FileReadStats {
    extents: usize,
}

#[derive(Clone, Copy)]
struct Cluster {
    index: u32,
    start_offset: u64,
    len_bytes: u32,
}

#[derive(Clone, Copy)]
struct Bpb {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sector_count: u16,
    num_fats: u8,
    root_entry_count: u16,
    fat_size_16: u16,
    total_sectors_16: u16,
    total_sectors_32: u32,
    fat_size_32: u32,
    root_cluster: u32,
}

impl Bpb {
    fn parse(reader: &mut BlockReader<'_>) -> Option<Self> {
        let mut raw = [0u8; 512];
        reader.read_exact(0, &mut raw).ok()?;

        let fat_size_16 = u16::from_le_bytes(raw[22..24].try_into().ok()?);
        let (fat_size_32, root_cluster) = if fat_size_16 == 0 {
            (
                u32::from_le_bytes(raw[36..40].try_into().ok()?),
                u32::from_le_bytes(raw[44..48].try_into().ok()?),
            )
        } else {
            (0, 0)
        };

        Some(Self {
            bytes_per_sector: u16::from_le_bytes(raw[11..13].try_into().ok()?),
            sectors_per_cluster: raw[13],
            reserved_sector_count: u16::from_le_bytes(raw[14..16].try_into().ok()?),
            num_fats: raw[16],
            root_entry_count: u16::from_le_bytes(raw[17..19].try_into().ok()?),
            fat_size_16,
            total_sectors_16: u16::from_le_bytes(raw[19..21].try_into().ok()?),
            total_sectors_32: u32::from_le_bytes(raw[32..36].try_into().ok()?),
            fat_size_32,
            root_cluster,
        })
    }

    fn fat_type(&self) -> FatType {
        let count_of_clusters = self.count_of_clusters();
        if count_of_clusters < 4085 {
            FatType::Fat12
        } else if count_of_clusters < 65525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        }
    }

    fn count_of_clusters(&self) -> u32 {
        let root_dir_sectors = ((self.root_entry_count as u32 * DIRECTORY_ENTRY_BYTES as u32)
            + (self.bytes_per_sector as u32 - 1))
            / self.bytes_per_sector as u32;
        let total_sectors = if self.total_sectors_16 != 0 {
            self.total_sectors_16 as u32
        } else {
            self.total_sectors_32
        };
        let data_sectors = total_sectors
            - (self.reserved_sector_count as u32
                + self.num_fats as u32 * self.fat_size_in_sectors()
                + root_dir_sectors);
        data_sectors / self.sectors_per_cluster as u32
    }

    fn fat_size_in_sectors(&self) -> u32 {
        if self.fat_size_16 != 0 {
            self.fat_size_16 as u32
        } else {
            self.fat_size_32
        }
    }

    fn fat_size_bytes(&self) -> usize {
        usize::try_from(self.fat_size_in_sectors()).unwrap() * self.bytes_per_sector as usize
    }

    fn root_directory_size(&self) -> usize {
        self.root_entry_count as usize * DIRECTORY_ENTRY_BYTES
    }

    fn root_directory_offset(&self) -> u64 {
        (self.reserved_sector_count as u64
            + self.num_fats as u64 * self.fat_size_in_sectors() as u64)
            * self.bytes_per_sector as u64
    }

    fn fat_offset(&self) -> u64 {
        self.reserved_sector_count as u64 * self.bytes_per_sector as u64
    }

    fn data_offset(&self) -> u64 {
        self.root_directory_size() as u64 + self.root_directory_offset()
    }

    fn cluster_offset(&self, cluster: u32) -> u64 {
        self.data_offset() + (u64::from(cluster) - 2) * u64::from(self.bytes_per_cluster())
    }

    fn bytes_per_cluster(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }

    fn maximum_valid_cluster(&self) -> u32 {
        self.count_of_clusters() + 1
    }
}

#[derive(Clone, Copy)]
enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

impl FatType {
    fn fat_entry_defective(self) -> u32 {
        match self {
            Self::Fat12 => 0xFF7,
            Self::Fat16 => 0xFFF7,
            Self::Fat32 => 0x0FFF_FFF7,
        }
    }
}

enum FileFatEntry {
    AllocatedCluster(u32),
    EndOfFile,
}

enum FatLookupError {
    FreeCluster,
    DefectiveCluster,
    UnspecifiedEntryOne,
    ReservedEntry,
}

fn classify_fat_entry(
    fat_type: FatType,
    entry: u32,
    maximum_valid_cluster: u32,
) -> Result<FileFatEntry, FatLookupError> {
    match entry {
        0 => Err(FatLookupError::FreeCluster),
        1 => Err(FatLookupError::UnspecifiedEntryOne),
        entry => {
            if entry <= maximum_valid_cluster {
                Ok(FileFatEntry::AllocatedCluster(entry))
            } else if entry < fat_type.fat_entry_defective() {
                Err(FatLookupError::ReservedEntry)
            } else if entry == fat_type.fat_entry_defective() {
                Err(FatLookupError::DefectiveCluster)
            } else {
                Ok(FileFatEntry::EndOfFile)
            }
        }
    }
}

fn fat_entry_of_nth_cluster(fat: &[u8], fat_type: FatType, cluster: u32) -> Option<u32> {
    debug_assert!(cluster >= 2);
    match fat_type {
        FatType::Fat32 => {
            let base = usize::try_from(cluster).ok()?.checked_mul(4)?;
            let entry: [u8; 4] = fat.get(base..base + 4)?.try_into().ok()?;
            Some(u32::from_le_bytes(entry) & 0x0FFF_FFFF)
        }
        FatType::Fat16 => {
            let base = usize::try_from(cluster).ok()?.checked_mul(2)?;
            let entry: [u8; 2] = fat.get(base..base + 2)?.try_into().ok()?;
            Some(u16::from_le_bytes(entry) as u32)
        }
        FatType::Fat12 => {
            let base = usize::try_from(cluster as u64 + u64::from(cluster / 2)).ok()?;
            let entry: [u8; 2] = fat.get(base..base + 2)?.try_into().ok()?;
            let entry = u16::from_le_bytes(entry);
            Some(if cluster & 1 == 0 {
                (entry & 0x0FFF) as u32
            } else {
                (entry >> 4) as u32
            })
        }
    }
}

fn parse_file_entry(entry: [u8; DIRECTORY_ENTRY_BYTES]) -> Result<File, ()> {
    let first_cluster_hi = u16::from_le_bytes(entry[20..22].try_into().map_err(|_| ())?);
    let first_cluster_lo = u16::from_le_bytes(entry[26..28].try_into().map_err(|_| ())?);
    Ok(File {
        first_cluster: ((first_cluster_hi as u32) << 16) | (first_cluster_lo as u32),
        file_size: u32::from_le_bytes(entry[28..32].try_into().map_err(|_| ())?),
        attributes: entry[11],
    })
}

fn short_name_matches(entry: &[u8; DIRECTORY_ENTRY_BYTES], target: &str) -> bool {
    let base = trim_spaces(&entry[0..8]);
    let ext = trim_spaces(&entry[8..11]);
    let target = target.as_bytes();

    if ext.is_empty() {
        eq_ignore_ascii_case(base, target)
    } else {
        let base_len = base.len();
        let ext_len = ext.len();
        target.len() == base_len + ext_len + 1
            && target[base_len] == b'.'
            && eq_ignore_ascii_case(base, &target[..base_len])
            && eq_ignore_ascii_case(ext, &target[base_len + 1..])
    }
}

fn trim_spaces(slice: &[u8]) -> &[u8] {
    let mut end = slice.len();
    while end > 0 && slice[end - 1] == b' ' {
        end -= 1;
    }
    &slice[..end]
}

fn eq_ignore_ascii_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(l, r)| l.eq_ignore_ascii_case(r))
}

struct LongName {
    chars: [u16; MAX_LONG_NAME_LEN],
    len_hint: usize,
    active: bool,
}

impl LongName {
    fn new() -> Self {
        Self {
            chars: [0; MAX_LONG_NAME_LEN],
            len_hint: 0,
            active: false,
        }
    }

    fn clear(&mut self) {
        self.len_hint = 0;
        self.active = false;
    }

    fn push(&mut self, entry: [u8; DIRECTORY_ENTRY_BYTES]) {
        let order = entry[0];
        let sequence = usize::from(order & LONG_NAME_ENTRY_ORDER_MASK);
        if sequence == 0 {
            self.clear();
            return;
        }

        if order & LONG_NAME_ENTRY_ORDER_LAST != 0 {
            self.clear();
            self.active = true;
        }

        if !self.active {
            return;
        }

        let start = (sequence - 1) * LONG_NAME_CHARS_PER_ENTRY;
        if start + LONG_NAME_CHARS_PER_ENTRY > self.chars.len() {
            self.clear();
            return;
        }

        for (idx, chunk) in entry[1..11]
            .chunks_exact(2)
            .chain(entry[14..26].chunks_exact(2))
            .chain(entry[28..32].chunks_exact(2))
            .enumerate()
        {
            self.chars[start + idx] = u16::from_le_bytes([chunk[0], chunk[1]]);
        }

        self.len_hint = self.len_hint.max(start + LONG_NAME_CHARS_PER_ENTRY);
    }

    fn matches_ascii(&self, target: &str) -> bool {
        if !self.active {
            return false;
        }

        let target = target.as_bytes();
        let exact_len = self.exact_len();
        if target.len() != exact_len {
            return false;
        }

        target
            .iter()
            .copied()
            .zip(self.chars.iter().copied())
            .take(exact_len)
            .all(|(target, actual)| actual == u16::from(target))
    }

    fn exact_len(&self) -> usize {
        self.chars[..self.len_hint]
            .iter()
            .position(|&ch| ch == 0 || ch == 0xFFFF)
            .unwrap_or(self.len_hint)
    }
}

mod directory_attributes {
    pub const READ_ONLY: u8 = 0x01;
    pub const HIDDEN: u8 = 0x02;
    pub const SYSTEM: u8 = 0x04;
    pub const VOLUME_ID: u8 = 0x08;
    pub const DIRECTORY: u8 = 0x10;

    pub const LONG_NAME: u8 = READ_ONLY | HIDDEN | SYSTEM | VOLUME_ID;
}
