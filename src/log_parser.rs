use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::mem;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LogRecord {
    pub insn_count: u64,
    pub address: u64,
    pub cpu: u8,
    pub store: u8,
    pub size: u8,
    pub _padding: [u8; 5],
}

impl LogRecord {
    pub const SIZE: usize = mem::size_of::<LogRecord>();

    pub fn deserialize(buffer: &mut [u8; Self::SIZE]) -> LogRecord {
        unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const _) }
    }
}

impl fmt::Debug for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "LogRecord {{ insn_count: {}, cpu: {}, store: {}, size: {}, address: 0x{:016x} }}",
            self.insn_count, self.cpu, self.store, self.size, self.address
        )
    }
}

pub struct LogParser {
    reader: BufReader<File>,
}

impl LogParser {
    pub fn new(filename: &str) -> io::Result<Self> {
        let file = File::open(filename)?;

        Ok(LogParser {
            reader: BufReader::with_capacity(64 * 1024, file),
        })
    }
}

impl Iterator for LogParser {
    type Item = io::Result<LogRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = [0u8; LogRecord::SIZE];
        match self.reader.read_exact(&mut buffer) {
            Ok(_) => Some(Ok(LogRecord::deserialize(&mut buffer))),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => None,
            Err(e) => Some(Err(e)),
        }
    }
}
