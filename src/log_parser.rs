use std::cmp;
use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::SeekFrom;
use std::io::{self, BufReader, Read, Seek};
use std::mem;
use std::str::FromStr;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LogRecord {
    pub logical_clock: u64,
    pub insn_count: u64,
    pub cpu: u8,
    pub store: u8,
    pub size: u8,
    pub _padding: [u8; 5],
    pub address: u64,
}

impl LogRecord {
    pub const SIZE: usize = mem::size_of::<LogRecord>();

    pub fn deserialize(buffer: &mut [u8; Self::SIZE]) -> LogRecord {
        unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const _) }
    }
    pub fn serialize(&self, buffer: &mut [u8; Self::SIZE]) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                self as *const LogRecord as *const u8,
                buffer.as_mut_ptr(),
                Self::SIZE,
            );
        }
    }
}

impl fmt::Display for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{},{},{},{},{},0x{:016x}",
            self.logical_clock, self.insn_count, self.cpu, self.store, self.size, self.address
        )
    }
}

impl FromStr for LogRecord {
    type Err = Box<dyn std::error::Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.trim().split(',').collect();
        if parts.len() != 6 {
            return Err("Record must have at least 5 fields".into());
        }
        Ok(LogRecord {
            logical_clock: parts[0].parse::<u64>()?,
            insn_count: parts[1].parse::<u64>()?,
            cpu: parts[2].parse()?,
            store: parts[3].parse()?,
            size: parts[4].parse()?,
            _padding: [0u8; 5],
            address: u64::from_str_radix(parts[5].trim_start_matches("0x"), 16)?,
        })
    }
}
impl fmt::Debug for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "LogRecord {{logical_clock: {}, insn_count: {}, cpu: {}, store: {}, size: {}, address: 0x{:016x} }}",
            self.logical_clock, self.insn_count, self.cpu, self.store, self.size, self.address
        )
    }
}

impl PartialEq for LogRecord {
    fn eq(&self, other: &Self) -> bool {
        self.logical_clock == other.logical_clock
        && self.cpu == other.cpu
    }
}

impl Eq for LogRecord {}

impl PartialOrd for LogRecord {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for LogRecord {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.logical_clock.cmp(&other.logical_clock) {
            cmp::Ordering::Equal => self.cpu.cmp(&other.cpu),
            ordering => ordering,
        }
    }
}

pub struct LogParser {
    reader: BufReader<File>,
    record_queue: VecDeque<LogRecord>,
    last_anchor_clock: u64,
    last_clock_step: f64,
    first_block_buffer: Option<Vec<LogRecord>>,
}

impl LogParser {
    pub fn new(filename: &str) -> io::Result<Self> {
        File::open(filename).map(|file| LogParser {
            reader: BufReader::new(file),
            record_queue: VecDeque::with_capacity(128),
            last_anchor_clock: 0,
            last_clock_step: 2.0,
            first_block_buffer: None,
        })
    }
    pub fn reset(&mut self) {
        self.reader
            .seek(SeekFrom::Start(0))
            .expect("failed to reset");
        self.record_queue.clear();
        self.last_anchor_clock = 0;
        self.last_clock_step = 2.0;
        self.first_block_buffer = None;
    }
    fn read_next_raw_block(&mut self) -> io::Result<Vec<LogRecord>> {
        let mut block = Vec::with_capacity(128);
        let mut buffer = [0u8; LogRecord::SIZE];
        for _ in 0..128 {
            match self.reader.read_exact(&mut buffer) {
                Ok(_) => block.push(LogRecord::deserialize(&mut buffer)),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }
        Ok(block)
    }

    fn load_and_interpolate_block(&mut self) -> io::Result<()> {

        if self.last_anchor_clock == 0 {
            let mut block1 = self.read_next_raw_block()?;
            let block2 = self.read_next_raw_block()?;
            let anchor_clock1 = block1[127].logical_clock;
            let anchor_clock2 = block2[127].logical_clock;

            let total_clock_delta = anchor_clock2.saturating_sub(anchor_clock1);
            let clock_step = total_clock_delta as f64 / 128.0;
            self.last_clock_step = clock_step;
            self.last_anchor_clock = anchor_clock1.saturating_sub((128.0 * clock_step) as u64);
            for (i, record) in block1.iter_mut().enumerate() {
                if record.logical_clock == 0 {
                    let steps_from_start = (i + 1) as f64;
                    record.logical_clock = self.last_anchor_clock + (steps_from_start * clock_step) as u64;
                }
            }
            self.last_anchor_clock = anchor_clock1;
            for record in block1 { self.record_queue.push_back(record); }
            self.first_block_buffer = Some(block2);
            return Ok(());
        }
        let mut block = if let Some(saved_block) = self.first_block_buffer.take() {
            saved_block
        } else {
            self.read_next_raw_block()?
        };
        if block.is_empty() { return Ok(()); }
        let idx = block.len() - 1;
        let anchor_clock = block[idx].logical_clock;
        if anchor_clock != 0 {
            let total_clock_delta = anchor_clock.saturating_sub(self.last_anchor_clock);
            let steps = (idx + 1) as f64;
            let current_clock_step = total_clock_delta as f64 / steps;
            
            self.last_clock_step = current_clock_step;

            for (i, record) in block.iter_mut().enumerate() {
                if i <= idx && record.logical_clock == 0 {
                    let steps_from_start = (i + 1) as f64;
                    record.logical_clock = self.last_anchor_clock + (steps_from_start * current_clock_step) as u64;
                }
            }
            self.last_anchor_clock = anchor_clock;
        } else {
            for record in block.iter_mut() {
                if record.logical_clock == 0 {
                    self.last_anchor_clock = self.last_anchor_clock + self.last_clock_step as u64;
                    record.logical_clock = self.last_anchor_clock;
                }
            }
        }
        for record in block {
            self.record_queue.push_back(record);
        }
        Ok(())
    }
}

impl Iterator for LogParser {
    type Item = io::Result<LogRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.record_queue.is_empty() {
            if let Err(e) = self.load_and_interpolate_block() {
                return Some(Err(e));
            }
        }
        self.record_queue.pop_front().map(Ok)
    }
}
