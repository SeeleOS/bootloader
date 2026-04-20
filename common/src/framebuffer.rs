use alloc::boxed::Box;
use bootloader_api::info::{FrameBufferInfo, PixelFormat};
use core::{fmt, ptr};
use os_terminal::{DrawTarget, Rgb, Terminal, font::BitmapFont};

struct FrameBufferDisplay {
    framebuffer: &'static mut [u8],
    info: FrameBufferInfo,
}

impl FrameBufferDisplay {
    fn write_pixel(&mut self, x: usize, y: usize, color: Rgb) {
        let pixel_offset = y * self.info.stride + x;
        let pixel = match self.info.pixel_format {
            PixelFormat::Rgb => [color.0, color.1, color.2, 0],
            PixelFormat::Bgr => [color.2, color.1, color.0, 0],
            PixelFormat::U8 => [
                if color.0 > 200 || color.1 > 200 || color.2 > 200 {
                    0xf
                } else {
                    0
                },
                0,
                0,
                0,
            ],
            other => {
                self.info.pixel_format = PixelFormat::Rgb;
                panic!("pixel format {:?} not supported in logger", other)
            }
        };
        let bytes_per_pixel = self.info.bytes_per_pixel;
        let byte_offset = pixel_offset * bytes_per_pixel;
        self.framebuffer[byte_offset..(byte_offset + bytes_per_pixel)]
            .copy_from_slice(&pixel[..bytes_per_pixel]);
        let _ = unsafe { ptr::read_volatile(&self.framebuffer[byte_offset]) };
    }
}

impl DrawTarget for FrameBufferDisplay {
    fn size(&self) -> (usize, usize) {
        (self.info.width, self.info.height)
    }

    fn draw_pixel(&mut self, x: usize, y: usize, color: Rgb) {
        self.write_pixel(x, y, color);
    }
}

/// Allows logging text to a pixel-based framebuffer.
pub struct FrameBufferWriter {
    terminal: Terminal<FrameBufferDisplay>,
}

impl FrameBufferWriter {
    /// Creates a new logger that uses the given framebuffer.
    pub fn new(framebuffer: &'static mut [u8], info: FrameBufferInfo) -> Self {
        let display = FrameBufferDisplay { framebuffer, info };
        let mut terminal = Terminal::new(display, Box::new(BitmapFont));
        terminal.clear();
        Self { terminal }
    }

    /// Erases all text on the screen. Resets `self.x_pos` and `self.y_pos`.
    pub fn clear(&mut self) {
        self.terminal.clear();
    }
}

unsafe impl Send for FrameBufferWriter {}
unsafe impl Sync for FrameBufferWriter {}

impl fmt::Write for FrameBufferWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.terminal.write_str(s)?;
        Ok(())
    }
}
