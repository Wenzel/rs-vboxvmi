//! Client for VBoxVMI, the introspection protocol served by a patched VirtualBox VM process over
//! a per-VM Unix domain socket (`SOCK_SEQPACKET`).
//!
//! The wire format is specified in the VirtualBox tree: `doc/technical/VBoxVMI-protocol.md`
//! and `include/VBox/vmm/vmi.h`. Linux only.

use std::convert::TryInto;
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

/// Protocol magic, the bytes "BVMI" on the wire.
pub const MAGIC: u32 = 0x494d_5642;
/// Protocol version spoken by this crate. Client and server must match exactly.
pub const VERSION: u32 = 1;

/// Maximum size of a message, header included.
const MSG_SIZE_MAX: usize = 64 * 1024;
const HDR_SIZE: usize = 16;
const MSG_HELLO: u16 = 1;
const MSG_F_REPLY: u16 = 1;

// VirtualBox status codes (iprt/err.h) the client tells apart.
const VERR_INVALID_MAGIC: i32 = -3;
const VERR_VERSION_MISMATCH: i32 = -11;
const VERR_ACCESS_DENIED: i32 = -38;
const VERR_RESOURCE_BUSY: i32 = -138;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("cannot connect to the VBoxVMI socket {path:?}: {source} (is VBoxInternal/VMI/Enabled set on the VM, and is the VM running?)")]
    Connect { path: PathBuf, source: io::Error },
    #[error("VBoxVMI socket I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("another VBoxVMI client is already connected to this VM")]
    Busy,
    #[error("the VBoxVMI server refused this user: only the user running the VM may connect")]
    AccessDenied,
    #[error("VBoxVMI protocol version mismatch: server speaks {server}, client speaks {client}")]
    VersionMismatch { server: u32, client: u32 },
    #[error("not a VBoxVMI server (magic {0:#010x})")]
    BadMagic(u32),
    #[error("VBoxVMI protocol error: {0}")]
    Protocol(String),
    #[error("VBoxVMI {request} failed with VirtualBox status {rc}")]
    Server { request: &'static str, rc: i32 },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Message header (`VMIMSGHDR`).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Header {
    size: u32,
    id: u32,
    kind: u16,
    flags: u16,
    rc: i32,
}

impl Header {
    fn encode(&self) -> [u8; HDR_SIZE] {
        let mut b = [0u8; HDR_SIZE];
        b[0..4].copy_from_slice(&self.size.to_le_bytes());
        b[4..8].copy_from_slice(&self.id.to_le_bytes());
        b[8..10].copy_from_slice(&self.kind.to_le_bytes());
        b[10..12].copy_from_slice(&self.flags.to_le_bytes());
        b[12..16].copy_from_slice(&self.rc.to_le_bytes());
        b
    }

    fn decode(b: &[u8]) -> Self {
        Header {
            size: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            id: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            kind: u16::from_le_bytes(b[8..10].try_into().unwrap()),
            flags: u16::from_le_bytes(b[10..12].try_into().unwrap()),
            rc: i32::from_le_bytes(b[12..16].try_into().unwrap()),
        }
    }
}

/// `VMIHELLO` body: (magic, version).
fn decode_hello(body: &[u8]) -> Result<(u32, u32)> {
    if body.len() != 8 {
        return Err(Error::Protocol(format!(
            "hello body of {} bytes",
            body.len()
        )));
    }
    Ok((
        u32::from_le_bytes(body[0..4].try_into().unwrap()),
        u32::from_le_bytes(body[4..8].try_into().unwrap()),
    ))
}

/// A connection to the VBoxVMI server of one VM, handshake done.
///
/// The server serves one client at a time; dropping the client disconnects it.
pub struct Client {
    fd: OwnedFd,
    next_id: u32,
    /// Receive buffer, reused for every message.
    buf: Vec<u8>,
}

impl Client {
    /// Connects to the VBoxVMI socket at `path` and performs the handshake.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let fd = connect_seqpacket(path).map_err(|source| Error::Connect {
            path: path.to_path_buf(),
            source,
        })?;
        let mut client = Client {
            fd,
            next_id: 1,
            buf: vec![0; MSG_SIZE_MAX],
        };

        // The server speaks first: it tells a refused client why.
        let (hdr, body) = client.recv()?;
        if hdr.kind != MSG_HELLO || hdr.flags != 0 || hdr.id != 0 {
            return Err(Error::Protocol(format!("unexpected greeting {:?}", hdr)));
        }
        match hdr.rc {
            VERR_RESOURCE_BUSY => return Err(Error::Busy),
            VERR_ACCESS_DENIED => return Err(Error::AccessDenied),
            rc if rc < 0 => {
                return Err(Error::Server {
                    request: "greeting",
                    rc,
                })
            }
            _ => {}
        }
        check_hello(body)?;

        let mut req = [0u8; 8];
        req[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        req[4..8].copy_from_slice(&VERSION.to_le_bytes());
        let (hdr, body) = client.request(MSG_HELLO, &req)?;
        match hdr.rc {
            VERR_VERSION_MISMATCH => {
                return Err(Error::VersionMismatch {
                    server: decode_hello(body)?.1,
                    client: VERSION,
                })
            }
            VERR_INVALID_MAGIC => return Err(Error::Protocol("server rejected our magic".into())),
            rc if rc < 0 => {
                return Err(Error::Server {
                    request: "hello",
                    rc,
                })
            }
            _ => {}
        }
        check_hello(body)?;
        Ok(client)
    }

    /// Sends a request and waits for its reply. Returns the reply header and body (valid until
    /// the next message); the caller checks the status.
    fn request(&mut self, kind: u16, body: &[u8]) -> Result<(Header, &[u8])> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1); // 0 is reserved for non-replies
        let size = HDR_SIZE + body.len();
        if size > MSG_SIZE_MAX {
            return Err(Error::Protocol(format!(
                "request of {} bytes is too big",
                size
            )));
        }
        let hdr = Header {
            size: size as u32,
            id,
            kind,
            flags: 0,
            rc: 0,
        }
        .encode();
        // Header and body as one record, without copying them together.
        let mut iov = [
            libc::iovec {
                iov_base: hdr.as_ptr() as *mut libc::c_void,
                iov_len: hdr.len(),
            },
            libc::iovec {
                iov_base: body.as_ptr() as *mut libc::c_void,
                iov_len: body.len(),
            },
        ];
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len() as _;
        loop {
            // MSG_NOSIGNAL: a server that went away is an error, not a SIGPIPE.
            let sent = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
            if sent >= 0 {
                break;
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err.into());
            }
        }

        let (reply, body) = self.recv()?;
        if reply.flags != MSG_F_REPLY || reply.id != id || reply.kind != kind {
            return Err(Error::Protocol(format!(
                "unexpected reply {:?} to request {} type {}",
                reply, id, kind
            )));
        }
        Ok((reply, body))
    }

    /// Receives one message into the reusable buffer.
    fn recv(&mut self) -> Result<(Header, &[u8])> {
        let n = loop {
            // MSG_TRUNC returns the real size of an oversized message.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                    libc::MSG_TRUNC,
                )
            };
            if n >= 0 {
                break n as usize;
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err.into());
            }
        };
        if n == 0 {
            return Err(Error::Protocol("the server closed the connection".into()));
        }
        if !(HDR_SIZE..=MSG_SIZE_MAX).contains(&n) {
            return Err(Error::Protocol(format!("message of {} bytes", n)));
        }
        let hdr = Header::decode(&self.buf);
        if hdr.size as usize != n {
            return Err(Error::Protocol(format!(
                "header says {} bytes, got {}",
                hdr.size, n
            )));
        }
        Ok((hdr, &self.buf[HDR_SIZE..n]))
    }
}

fn check_hello(body: &[u8]) -> Result<()> {
    let (magic, version) = decode_hello(body)?;
    if magic != MAGIC {
        return Err(Error::BadMagic(magic));
    }
    if version != VERSION {
        return Err(Error::VersionMismatch {
            server: version,
            client: VERSION,
        });
    }
    Ok(())
}

fn connect_seqpacket(path: &Path) -> io::Result<OwnedFd> {
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    // Keep the terminating NUL.
    if bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path too long",
        ));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }

    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast(),
            mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout_matches_vmimsghdr() {
        let hdr = Header {
            size: 0x18,
            id: 7,
            kind: MSG_HELLO,
            flags: MSG_F_REPLY,
            rc: VERR_RESOURCE_BUSY,
        };
        let b = hdr.encode();
        assert_eq!(
            b,
            [0x18, 0, 0, 0, 7, 0, 0, 0, 1, 0, 1, 0, 0x76, 0xff, 0xff, 0xff]
        );
        assert_eq!(Header::decode(&b), hdr);
        assert_eq!(&MAGIC.to_le_bytes(), b"BVMI");
    }
}
