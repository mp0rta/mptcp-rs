//! Linux TUN device (IFF_TUN | IFF_NO_PI, nonblocking). The only module with `unsafe`.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

// libc 0.2 has no TUNSETIFF: _IOW('T', 202, int) = 0x400454ca on Linux.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

pub struct Tun {
    fd: OwnedFd,
}

impl Tun {
    pub fn open(name: &str) -> io::Result<Tun> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad interface name",
            ));
        }
        // SAFETY: valid NUL-terminated path; the returned fd is owned below.
        let raw = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, valid fd that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: ifreq is plain data; all-zero is valid.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (d, s) in ifr.ifr_name.iter_mut().zip(bytes) {
            *d = *s as libc::c_char;
        }
        ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
        // SAFETY: TUNSETIFF reads one struct ifreq through the pointer.
        if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut ifr) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Tun { fd })
    }

    /// `WouldBlock` when no packet is queued.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: buf is valid for buf.len() writable bytes.
        let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        usize::try_from(n).map_err(|_| io::Error::last_os_error())
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: buf is valid for buf.len() readable bytes.
        let n = unsafe { libc::write(self.fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        usize::try_from(n).map_err(|_| io::Error::last_os_error())
    }

    /// Waits until a packet can be read; `None` waits forever. `Ok(false)` = timed out.
    pub fn wait_readable(&self, timeout: Option<Duration>) -> io::Result<bool> {
        let mut p = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Round up so a sub-millisecond timeout does not spin.
        let ms = timeout.map_or(-1, |d| {
            d.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32
        });
        // SAFETY: one valid pollfd.
        let r = unsafe { libc::poll(&mut p, 1, ms) };
        if r < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(e)
            };
        }
        Ok(r > 0)
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
