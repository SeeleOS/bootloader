use crate::{framebuffer::FrameBufferWriter, serial::SerialPort};
use bootloader_api::info::FrameBufferInfo;
use conquer_once::spin::OnceCell;
use core::fmt::{self, Write};
use spinning_top::Spinlock;

/// The global logger instance used for the `log` crate.
pub static LOGGER: OnceCell<LockedLogger> = OnceCell::uninit();

/// A logger instance protected by a spinlock.
pub struct LockedLogger {
    framebuffer: Option<Spinlock<FrameBufferWriter>>,
    serial: Option<Spinlock<SerialPort>>,
}

impl LockedLogger {
    /// Create a new instance that logs to the given framebuffer.
    pub fn new(
        framebuffer: &'static mut [u8],
        info: FrameBufferInfo,
        frame_buffer_logger_status: bool,
        serial_logger_status: bool,
    ) -> Self {
        let framebuffer = match frame_buffer_logger_status {
            true => Some(Spinlock::new(FrameBufferWriter::new(framebuffer, info))),
            false => None,
        };

        let serial = match serial_logger_status {
            true => Some(Spinlock::new(unsafe { SerialPort::init() })),
            false => None,
        };

        LockedLogger {
            framebuffer,
            serial,
        }
    }

    /// Force-unlocks the logger to prevent a deadlock.
    ///
    /// ## Safety
    /// This method is not memory safe and should be only used when absolutely necessary.
    pub unsafe fn force_unlock(&self) {
        if let Some(framebuffer) = &self.framebuffer {
            unsafe { framebuffer.force_unlock() };
        }
        if let Some(serial) = &self.serial {
            unsafe { serial.force_unlock() };
        }
    }
}

impl log::Log for LockedLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if let Some(framebuffer) = &self.framebuffer {
            let mut framebuffer = framebuffer.lock();
            write_terminal_record(&mut *framebuffer, record).unwrap();
        }
        if let Some(serial) = &self.serial {
            let mut serial = serial.lock();
            write_serial_record(&mut *serial, record).unwrap();
        }
    }

    fn flush(&self) {}
}

fn write_terminal_record(writer: &mut impl Write, record: &log::Record) -> fmt::Result {
    match record.level() {
        log::Level::Error => writeln!(
            writer,
            "\x1b[1;97;41m Error \x1b[0m \x1b[1;31m{}\x1b[0m",
            record.args()
        ),
        log::Level::Warn => writeln!(
            writer,
            "\x1b[1;97;43m  Warn \x1b[0m \x1b[1;33m{}\x1b[0m",
            record.args()
        ),
        log::Level::Info => writeln!(writer, "\x1b[1;97;104m  Info \x1b[0m {}", record.args()),
        log::Level::Debug => writeln!(writer, "\x1b[1;97;100m Debug \x1b[0m {}", record.args()),
        log::Level::Trace => writeln!(
            writer,
            "\x1b[97;100m Trace \x1b[0m \x1b[90m{}\x1b[0m",
            record.args()
        ),
    }
}

fn write_serial_record(writer: &mut impl Write, record: &log::Record) -> fmt::Result {
    writeln!(writer, "{:5}: {}", record.level(), record.args())
}
