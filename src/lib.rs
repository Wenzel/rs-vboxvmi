//! Client for VBoxVMI, the introspection protocol served by a patched VirtualBox VM process over
//! a per-VM Unix domain socket (`SOCK_SEQPACKET`).
//!
//! The wire format is specified in the VirtualBox tree: `doc/technical/VBoxVMI-protocol.md`
//! and `include/VBox/vmm/vmi.h`. Linux only.

use std::collections::VecDeque;
use std::convert::TryInto;
use std::io;
use std::mem;
use std::ops::Range;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Protocol magic, the bytes "BVMI" on the wire.
pub const MAGIC: u32 = 0x494d_5642;
/// Protocol version spoken by this crate. Client and server must match exactly.
pub const VERSION: u32 = 2;

/// Maximum size of a message, header included.
const MSG_SIZE_MAX: usize = 64 * 1024;
const HDR_SIZE: usize = 16;
const BODY_SIZE_MAX: usize = MSG_SIZE_MAX - HDR_SIZE;
const MSG_HELLO: u16 = 1;
const MSG_PHYS_READ: u16 = 2;
const MSG_RAM_RANGES: u16 = 3;
const MSG_PAUSE: u16 = 4;
const MSG_RESUME: u16 = 5;
const MSG_VCPU_COUNT: u16 = 6;
const MSG_REGS_READ: u16 = 7;
const MSG_REGS_WRITE: u16 = 8;
const MSG_PHYS_WRITE: u16 = 9;
const MSG_INTERCEPT_SET: u16 = 0x0a;
const MSG_INTERCEPT_CLEAR: u16 = 0x0b;
const MSG_EVENT_REPLY: u16 = 0x0c;
/// `VMIINTERCEPT` and `VMIEVENT` kinds.
const INTERCEPT_BREAKPOINT: u32 = 1;
const INTERCEPT_SINGLESTEP: u32 = 2;
const INTERCEPT_CR_WRITE: u32 = 3;
const INTERCEPT_MSR_WRITE: u32 = 4;
const INTERCEPT_PAGE_ACCESS: u32 = 5;
const EVENT_REPLY_F_REINJECT: u32 = 1;
/// `VMIEVENTREPLY` actions and the maximum emulation read data.
const EVENT_REPLY_CONTINUE: u32 = 0;
const EVENT_REPLY_EMULATE: u32 = 1;
const EVENT_REPLY_EMULATE_READ_DATA: u32 = 2;
const EVENT_REPLY_EMULATE_INSN: u32 = 3;
const EVENT_REPLY_DATA_MAX: usize = 256;
const MSG_EVENT: u16 = 0x0d;
const MSG_PAGE_ACCESS_SET: u16 = 0x0e;
const MSG_PAGE_ACCESS_GET: u16 = 0x0f;
/// Page access bits (`fAccess`): the access a Page access restriction allows, or the single
/// access a page-access event attempted.
pub const PAGE_ACCESS_R: u32 = 1;
pub const PAGE_ACCESS_W: u32 = 2;
pub const PAGE_ACCESS_X: u32 = 4;
/// Guest page size: physical reads have a status per guest page.
pub const PAGE_SIZE: u64 = 4096;
/// `VMIPHYSRANGE` and `VMIRAMRANGE` size.
const RANGE_SIZE: usize = 16;
const MSG_F_REPLY: u16 = 1;

// VirtualBox status codes (iprt/err.h) the client tells apart.
const VERR_INVALID_PARAMETER: i32 = -2;
const VERR_INVALID_MAGIC: i32 = -3;
const VERR_VERSION_MISMATCH: i32 = -11;
const VERR_NOT_SUPPORTED: i32 = -37;
const VERR_ACCESS_DENIED: i32 = -38;
const VERR_INVALID_STATE: i32 = -79;
const VERR_RESOURCE_BUSY: i32 = -138;
const VERR_INVALID_CPU_ID: i32 = -1018;
const VERR_DBGF_ALREADY_ATTACHED: i32 = -1201;
const VERR_VM_INVALID_VM_STATE: i32 = -1907;

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
    #[error("VBoxVMI {request} refused: VirtualBox controls the VM's run state (powering on or off, saving or restoring state, snapshot, teleport, configuration change, or paused by the host's power management); retry once it settles")]
    VmState { request: &'static str },
    #[error("VBoxVMI: the VM has no vCPU {0}")]
    NoSuchVcpu(u32),
    #[error("VBoxVMI register write refused (VERR_INVALID_PARAMETER): a value the CPU would not load (RFLAGS, control register, EFER or MSR), or a nonzero reserved field; nothing was written")]
    InvalidRegisters,
    #[error("VBoxVMI intercept or page access refused: the VirtualBox debugger is attached to the VM; detach it first")]
    DebuggerAttached,
    #[error("VBoxVMI event reply refused: vCPU {0} is not waiting for a reply")]
    NotParked(u32),
    #[error("VBoxVMI event reply refused (VERR_INVALID_PARAMETER): it does not fit the event (reinjection only at a breakpoint event, emulation and read data only at a page-access event, instruction bytes only at a breakpoint event); the vCPU stays parked")]
    InvalidReply,
    #[error("VBoxVMI {request} is not supported on this VM (single step, CR, MSR and page access intercepts and page access need VT-x; CR only 0, 3 and 4; execute-only page access needs EPT execute-only support)")]
    NotSupported { request: &'static str },
}

/// What an Intercept stops a vCPU on (`VMIINTERCEPT` kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptKind {
    /// An `int3` instruction the vCPU executes.
    Breakpoint,
    /// Every instruction boundary of the vCPU.
    Singlestep,
    /// A write to control register 0, 3 or 4 (`MOV CRx`), before it takes effect.
    CrWrite(u32),
    /// A `WRMSR` to the MSR with this index, before it takes effect.
    MsrWrite(u32),
    /// A vCPU access a Page access restriction denies (see [`Client::set_page_access`]), before
    /// it takes effect. Without it, the vCPU performs the access unreported.
    PageAccess,
}

/// A VMI event (`VMIEVENT`) received from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// The vCPU parked at this event.
    pub vcpu: u32,
    pub kind: EventKind,
}

/// Why the vCPU parked. Only the matching vCPU waits for the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// The `int3` at `gpa` was intercepted; RIP still points to it. Reinjection delivers #BP.
    Breakpoint { gpa: u64, insn_len: u32 },
    /// At the next instruction boundary; `gpa` is the physical address at RIP, `u64::MAX` if RIP
    /// is not mapped (a step onto a page the guest has not faulted in yet).
    Singlestep { gpa: u64 },
    /// A `MOV CRx` about to write `new` (CR3: PCID no-flush bit 63 cleared) over `old`; RIP at the
    /// instruction, which executes unchanged after a reply without reinjection.
    CrWrite { cr: u32, old: u64, new: u64 },
    /// A `WRMSR` about to write `new` (EDX:EAX) over `old` (0 if VirtualBox does not implement the
    /// MSR); RIP at the instruction, which executes unchanged after a reply without reinjection.
    MsrWrite { msr: u32, old: u64, new: u64 },
    /// A vCPU `access` (one `PAGE_ACCESS_*` bit) to `gpa` denied by a Page access restriction,
    /// before it takes effect; `gva` is the guest-linear address, 0 if the CPU reported none. RIP
    /// at the instruction; a [`Reply::Continue`] retries the access, reinjection is refused.
    PageAccess { gpa: u64, gva: u64, access: u32 },
}

/// How [`Client::reply_event`] releases a parked vCPU (`VMIEVENTREPLY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply<'a> {
    /// Continue at RIP: the instruction executes, a page access is retried (it faults again
    /// unless the restriction was lifted). `reinject` delivers a breakpoint event's #BP to the
    /// guest as if it had not been intercepted; refused for other events.
    Continue { reinject: bool },
    /// At a page-access event: run the instruction once with every Page access restriction
    /// ignored.
    Emulate,
    /// At a page-access event: like [`Reply::Emulate`], the instruction's memory reads returning
    /// these 1 to 256 bytes in order.
    EmulateReadData(&'a [u8]),
    /// At a breakpoint event: run these instruction bytes at RIP instead of guest memory.
    EmulateInsn([u8; 16]),
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

/// `VMIX86SEG` and `VMIX86DTR` size.
const SEG_SIZE: usize = 16;
/// `VMIX86REGS` size.
const REGS_SIZE: usize = 392;

/// A segment register (`VMIX86SEG`): the selector and its hidden base and limit. The attributes
/// are not part of the protocol; a write keeps them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub base: u64,
    /// In bytes, the granularity applied.
    pub limit: u32,
    pub selector: u16,
}

/// A descriptor table register, GDTR or IDTR (`VMIX86DTR`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TableRegister {
    pub base: u64,
    pub limit: u16,
}

/// The registers of an x86 vCPU (`VMIX86REGS`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct X86Registers {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    /// The architectural bits.
    pub rflags: u64,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    /// MSRs; one the guest CPU doesn't have reads as 0.
    pub efer: u64,
    pub star: u64,
    pub lstar: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub apic_base: u64,
    pub es: Segment,
    pub cs: Segment,
    pub ss: Segment,
    pub ds: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub ldtr: Segment,
    pub tr: Segment,
    pub gdtr: TableRegister,
    pub idtr: TableRegister,
}

impl X86Registers {
    /// The 64-bit fields in wire order, up to the segments.
    fn u64_fields(&mut self) -> [&mut u64; 29] {
        [
            &mut self.rax,
            &mut self.rcx,
            &mut self.rdx,
            &mut self.rbx,
            &mut self.rsp,
            &mut self.rbp,
            &mut self.rsi,
            &mut self.rdi,
            &mut self.r8,
            &mut self.r9,
            &mut self.r10,
            &mut self.r11,
            &mut self.r12,
            &mut self.r13,
            &mut self.r14,
            &mut self.r15,
            &mut self.rip,
            &mut self.rflags,
            &mut self.cr0,
            &mut self.cr2,
            &mut self.cr3,
            &mut self.cr4,
            &mut self.efer,
            &mut self.star,
            &mut self.lstar,
            &mut self.sysenter_cs,
            &mut self.sysenter_esp,
            &mut self.sysenter_eip,
            &mut self.apic_base,
        ]
    }

    /// The segment registers in wire order.
    fn segments(&mut self) -> [&mut Segment; 8] {
        [
            &mut self.es,
            &mut self.cs,
            &mut self.ss,
            &mut self.ds,
            &mut self.fs,
            &mut self.gs,
            &mut self.ldtr,
            &mut self.tr,
        ]
    }

    fn encode(&self) -> [u8; REGS_SIZE] {
        // The accessors borrow mutably: encode a copy.
        let mut regs = self.clone();
        let mut b = [0u8; REGS_SIZE];
        let mut off = 0;
        for v in regs.u64_fields() {
            b[off..off + 8].copy_from_slice(&v.to_le_bytes());
            off += 8;
        }
        for seg in regs.segments() {
            b[off..off + 8].copy_from_slice(&seg.base.to_le_bytes());
            b[off + 8..off + 12].copy_from_slice(&seg.limit.to_le_bytes());
            b[off + 12..off + 14].copy_from_slice(&seg.selector.to_le_bytes());
            off += SEG_SIZE;
        }
        for dtr in [&regs.gdtr, &regs.idtr] {
            b[off..off + 8].copy_from_slice(&dtr.base.to_le_bytes());
            b[off + 8..off + 10].copy_from_slice(&dtr.limit.to_le_bytes());
            off += SEG_SIZE;
        }
        debug_assert_eq!(off, REGS_SIZE);
        b
    }

    fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != REGS_SIZE {
            return Err(Error::Protocol(format!(
                "register read reply of {} bytes",
                b.len()
            )));
        }
        let u64_at = |off: usize| u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
        let mut regs = X86Registers::default();
        let mut off = 0;
        for v in regs.u64_fields() {
            *v = u64_at(off);
            off += 8;
        }
        for seg in regs.segments() {
            seg.base = u64_at(off);
            seg.limit = u32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap());
            seg.selector = u16::from_le_bytes(b[off + 12..off + 14].try_into().unwrap());
            off += SEG_SIZE;
        }
        for dtr in [&mut regs.gdtr, &mut regs.idtr] {
            dtr.base = u64_at(off);
            dtr.limit = u16::from_le_bytes(b[off + 8..off + 10].try_into().unwrap());
            off += SEG_SIZE;
        }
        Ok(regs)
    }
}

/// A connection to the VBoxVMI server of one VM, handshake done.
///
/// The server serves one client at a time; dropping the client disconnects it.
pub struct Client {
    fd: OwnedFd,
    next_id: u32,
    /// Receive buffer, reused for every message.
    buf: Vec<u8>,
    events: VecDeque<Event>,
}

impl Client {
    /// Connects to the VBoxVMI socket at `path` and performs the handshake.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let fd = connect_seqpacket(path).map_err(|source| Error::Connect {
            path: path.to_path_buf(),
            source,
        })?;
        Client::handshake(fd)
    }

    /// Performs the handshake on a connected socket.
    fn handshake(fd: OwnedFd) -> Result<Self> {
        let mut client = Client {
            fd,
            next_id: 1,
            buf: vec![0; MSG_SIZE_MAX],
            events: VecDeque::new(),
        };

        // The server speaks first: it tells a refused client why.
        let hdr = client.recv()?;
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
        check_hello(client.body(hdr))?;

        let req = u32_pair(MAGIC, VERSION);
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

    /// Reads guest physical memory into each `(address, buffer)` pair, in as few requests as the
    /// message size allows (several ranges per request, about 60 KiB of data per request).
    ///
    /// Appends a VirtualBox status per guest page that the ranges overlap, in order: a
    /// non-negative status if the page was read, otherwise why it is unreadable
    /// (`VERR_PGM_PHYS_PAGE_RESERVED` -1618 for MMIO,
    /// `VERR_PGM_INVALID_GC_PHYSICAL_ADDRESS` -1605 for no memory). Unreadable bytes are zeros.
    /// An unreadable page is not an error. If a later request fails, statuses and bytes from all
    /// completed requests are retained.
    pub fn read_physical(
        &mut self,
        ranges: &mut [(u64, &mut [u8])],
        status: &mut Vec<i32>,
    ) -> Result<()> {
        // Validate the complete operation before the first request. `addr + len - 1` permits a
        // non-empty range whose final byte is u64::MAX.
        for (addr, buf) in ranges.iter() {
            if !buf.is_empty() && addr.checked_add(buf.len() as u64 - 1).is_none() {
                return Err(Error::Protocol(format!(
                    "range of {} bytes at {:#x} wraps around",
                    buf.len(),
                    addr
                )));
            }
        }

        // The request being built: per wire range (index in `ranges`, offset in its buffer,
        // length, pages), and the reply size it needs.
        let mut batch: Vec<(usize, usize, usize, usize)> = Vec::new();
        let mut reply_size = 0;
        for i in 0..ranges.len() {
            let (addr, len) = (ranges[i].0, ranges[i].1.len());
            let mut off = 0;
            while off < len {
                let page_len =
                    (len - off).min((PAGE_SIZE - (addr + off as u64) % PAGE_SIZE) as usize);
                let cost = 4 + page_len;
                let mut can_merge =
                    matches!(batch.last(), Some(&(j, o, l, _)) if j == i && o + l == off);
                let request_size = (batch.len() + usize::from(!can_merge)) * RANGE_SIZE;
                if reply_size + cost > BODY_SIZE_MAX || request_size > BODY_SIZE_MAX {
                    self.read_batch(ranges, &batch, status)?;
                    batch.clear();
                    reply_size = 0;
                    can_merge = false;
                }
                if can_merge {
                    let (_, _, length, pages) = batch.last_mut().unwrap();
                    *length += page_len;
                    *pages += 1;
                } else {
                    batch.push((i, off, page_len, 1));
                }
                reply_size += cost;
                off += page_len;
            }
        }
        if !batch.is_empty() {
            self.read_batch(ranges, &batch, status)?;
        }
        Ok(())
    }

    /// Sends one `VMI_MSG_PHYS_READ` for `batch` (see `read_physical`).
    fn read_batch(
        &mut self,
        ranges: &mut [(u64, &mut [u8])],
        batch: &[(usize, usize, usize, usize)],
        status: &mut Vec<i32>,
    ) -> Result<()> {
        let mut req = Vec::with_capacity(batch.len() * RANGE_SIZE);
        for &(i, off, len, _) in batch {
            req.extend_from_slice(&(ranges[i].0 + off as u64).to_le_bytes());
            req.extend_from_slice(&(len as u32).to_le_bytes());
            req.extend_from_slice(&0u32.to_le_bytes());
        }
        let (hdr, body) = self.request(MSG_PHYS_READ, &req)?;
        if hdr.rc < 0 {
            return Err(Error::Server {
                request: "physical read",
                rc: hdr.rc,
            });
        }
        let pages: usize = batch.iter().map(|b| b.3).sum();
        let bytes: usize = batch.iter().map(|b| b.2).sum();
        if body.len() != 4 * pages + bytes {
            return Err(Error::Protocol(format!(
                "physical read reply of {} bytes, expected {}",
                body.len(),
                4 * pages + bytes
            )));
        }
        let (stat, mut data) = body.split_at(4 * pages);
        status.extend(
            stat.chunks(4)
                .map(|s| i32::from_le_bytes(s.try_into().unwrap())),
        );
        for &(i, off, len, _) in batch {
            ranges[i].1[off..off + len].copy_from_slice(&data[..len]);
            data = &data[len..];
        }
        Ok(())
    }

    /// Writes each `(address, bytes)` pair to guest physical RAM. Requests are split to fit the
    /// wire limit. Appends a VirtualBox status per overlapped guest page, in range order; a
    /// negative page status (including MMIO or unmapped memory) does not fail the request.
    /// If a later request fails, statuses from completed requests are retained.
    pub fn write_physical(&mut self, ranges: &[(u64, &[u8])], status: &mut Vec<i32>) -> Result<()> {
        for (addr, data) in ranges.iter() {
            if !data.is_empty() && addr.checked_add(data.len() as u64 - 1).is_none() {
                return Err(Error::Protocol(format!(
                    "range of {} bytes at {:#x} wraps around",
                    data.len(),
                    addr
                )));
            }
        }

        // Per wire range: input index, offset, length and overlapped guest pages.
        let mut batch: Vec<(usize, usize, usize, usize)> = Vec::new();
        let mut request_size = 4; // cRanges precedes the descriptors and data.
        let mut reply_size = 0;
        for (i, &(addr, data)) in ranges.iter().enumerate() {
            let mut off = 0;
            while off < data.len() {
                let page_len =
                    (data.len() - off).min((PAGE_SIZE - (addr + off as u64) % PAGE_SIZE) as usize);
                let mut can_merge =
                    matches!(batch.last(), Some(&(j, o, l, _)) if j == i && o + l == off);
                let cost = page_len + if can_merge { 0 } else { RANGE_SIZE };
                if request_size + cost > BODY_SIZE_MAX || reply_size + 4 > BODY_SIZE_MAX {
                    self.write_batch(ranges, &batch, request_size, status)?;
                    batch.clear();
                    request_size = 4;
                    reply_size = 0;
                    can_merge = false;
                }
                if can_merge {
                    let (_, _, length, pages) = batch.last_mut().unwrap();
                    *length += page_len;
                    *pages += 1;
                    request_size += page_len;
                } else {
                    batch.push((i, off, page_len, 1));
                    request_size += RANGE_SIZE + page_len;
                }
                reply_size += 4;
                off += page_len;
            }
        }
        if !batch.is_empty() {
            self.write_batch(ranges, &batch, request_size, status)?;
        }
        Ok(())
    }

    /// Sends one `VMI_MSG_PHYS_WRITE` for `batch` (see `write_physical`).
    fn write_batch(
        &mut self,
        ranges: &[(u64, &[u8])],
        batch: &[(usize, usize, usize, usize)],
        request_size: usize,
        status: &mut Vec<i32>,
    ) -> Result<()> {
        let mut req = Vec::with_capacity(request_size);
        req.extend_from_slice(&(batch.len() as u32).to_le_bytes());
        for &(i, off, len, _) in batch {
            req.extend_from_slice(&(ranges[i].0 + off as u64).to_le_bytes());
            req.extend_from_slice(&(len as u32).to_le_bytes());
            req.extend_from_slice(&0u32.to_le_bytes());
        }
        for &(i, off, len, _) in batch {
            req.extend_from_slice(&ranges[i].1[off..off + len]);
        }
        let (hdr, body) = self.request(MSG_PHYS_WRITE, &req)?;
        if hdr.rc < 0 {
            return Err(Error::Server {
                request: "physical write",
                rc: hdr.rc,
            });
        }
        let expected = batch.iter().map(|b| b.3).sum::<usize>() * 4;
        if body.len() != expected {
            return Err(Error::Protocol(format!(
                "physical write reply of {} bytes, expected {}",
                body.len(),
                expected
            )));
        }
        status.extend(
            body.chunks(4)
                .map(|s| i32::from_le_bytes(s.try_into().unwrap())),
        );
        Ok(())
    }

    /// The guest's RAM ranges (not ROM, MMIO or MMIO2), sorted, contiguous ones merged. The end
    /// of the last one is the max physical address. Never empty.
    pub fn ram_ranges(&mut self) -> Result<Vec<Range<u64>>> {
        let (hdr, body) = self.request(MSG_RAM_RANGES, &[])?;
        if hdr.rc < 0 {
            return Err(Error::Server {
                request: "RAM ranges",
                rc: hdr.rc,
            });
        }
        if body.is_empty() || body.len() % RANGE_SIZE != 0 {
            return Err(Error::Protocol(format!(
                "RAM ranges reply of {} bytes",
                body.len()
            )));
        }
        body.chunks(RANGE_SIZE)
            .map(|r| {
                let first = u64::from_le_bytes(r[0..8].try_into().unwrap());
                let last = u64::from_le_bytes(r[8..16].try_into().unwrap());
                // An end-exclusive Range can't hold a range ending at u64::MAX.
                match last.checked_add(1) {
                    Some(end) if first <= last => Ok(first..end),
                    _ => Err(Error::Protocol(format!(
                        "RAM range {:#x}-{:#x}",
                        first, last
                    ))),
                }
            })
            .collect()
    }

    /// Pauses the VM (`VMI_MSG_PAUSE`) with VirtualBox's standard pause: the VM shows as `Paused`
    /// to other API clients (e.g. `VBoxManage showvminfo`). Returns once every vCPU has stopped.
    /// A no-op if the VM is paused already. Not counted: a single [`Client::resume`] resumes the
    /// VM however many times it was paused, by anyone.
    pub fn pause(&mut self) -> Result<()> {
        self.pause_or_resume(MSG_PAUSE, "pause")
    }

    /// Resumes the VM (`VMI_MSG_RESUME`); a no-op if it is running already.
    pub fn resume(&mut self) -> Result<()> {
        self.pause_or_resume(MSG_RESUME, "resume")
    }

    fn pause_or_resume(&mut self, kind: u16, request: &'static str) -> Result<()> {
        let (hdr, body) = self.request(kind, &[])?;
        match hdr.rc {
            VERR_VM_INVALID_VM_STATE => Err(Error::VmState { request }),
            rc if rc < 0 => Err(Error::Server { request, rc }),
            _ if !body.is_empty() => Err(Error::Protocol(format!(
                "{} reply of {} bytes",
                request,
                body.len()
            ))),
            _ => Ok(()),
        }
    }

    /// The number of vCPUs (`VMI_MSG_VCPU_COUNT`), at least 1 and fixed for the VM's lifetime.
    pub fn vcpu_count(&mut self) -> Result<u32> {
        let (hdr, body) = self.request(MSG_VCPU_COUNT, &[])?;
        if hdr.rc < 0 {
            return Err(Error::Server {
                request: "vCPU count",
                rc: hdr.rc,
            });
        }
        match body.try_into().map(u32::from_le_bytes) {
            Ok(count) if count > 0 => Ok(count),
            _ => Err(Error::Protocol(format!("vCPU count reply {:02x?}", body))),
        }
    }

    /// Reads the registers of vCPU `vcpu` (`VMI_MSG_REGS_READ`), in one request. Served between
    /// two instructions of that vCPU: a consistent snapshot of it, also while the VM runs.
    pub fn read_registers(&mut self, vcpu: u32) -> Result<X86Registers> {
        let req = u32_pair(vcpu, 0);
        let (hdr, body) = self.request(MSG_REGS_READ, &req)?;
        match hdr.rc {
            VERR_INVALID_CPU_ID => Err(Error::NoSuchVcpu(vcpu)),
            rc if rc < 0 => Err(Error::Server {
                request: "register read",
                rc,
            }),
            _ => X86Registers::decode(body),
        }
    }

    /// Writes the registers of vCPU `vcpu` (`VMI_MSG_REGS_WRITE`), in one request, all at once
    /// between two instructions of that vCPU, also while the VM runs. All or nothing: a value the
    /// CPU would not load (e.g. RFLAGS bit 1 clear, a reserved control register bit, an MSR value
    /// `WRMSR` refuses) fails the write with [`Error::InvalidRegisters`]. Registers keeping their
    /// value are not touched. Segment selectors, bases and limits are raw state: no descriptor
    /// table load, the attributes are kept. Refused unless the VM is running or paused.
    pub fn write_registers(&mut self, vcpu: u32, regs: &X86Registers) -> Result<()> {
        let mut req = [0u8; 8 + REGS_SIZE];
        req[..8].copy_from_slice(&u32_pair(vcpu, 0));
        req[8..].copy_from_slice(&regs.encode());
        let request = "register write";
        let (hdr, body) = self.request(MSG_REGS_WRITE, &req)?;
        match hdr.rc {
            VERR_INVALID_CPU_ID => Err(Error::NoSuchVcpu(vcpu)),
            VERR_INVALID_PARAMETER => Err(Error::InvalidRegisters),
            VERR_VM_INVALID_VM_STATE => Err(Error::VmState { request }),
            rc if rc < 0 => Err(Error::Server { request, rc }),
            _ if !body.is_empty() => Err(Error::Protocol(format!(
                "{} reply of {} bytes",
                request,
                body.len()
            ))),
            _ => Ok(()),
        }
    }

    /// Sets an Intercept of `kind` on vCPU `vcpu` (`VMI_MSG_INTERCEPT_SET`): the vCPU then raises
    /// an [`Event`] and parks until [`Client::reply_event`]. Idempotent; allowed while the VM runs
    /// or is paused, also while handling an event. Refused with [`Error::DebuggerAttached`] while
    /// the VirtualBox debugger is attached.
    pub fn set_intercept(&mut self, vcpu: u32, kind: InterceptKind) -> Result<()> {
        self.intercept(MSG_INTERCEPT_SET, vcpu, kind)
    }

    /// Clears an Intercept of `kind` on vCPU `vcpu` (`VMI_MSG_INTERCEPT_CLEAR`). Idempotent.
    pub fn clear_intercept(&mut self, vcpu: u32, kind: InterceptKind) -> Result<()> {
        self.intercept(MSG_INTERCEPT_CLEAR, vcpu, kind)
    }

    fn intercept(&mut self, msg: u16, vcpu: u32, kind: InterceptKind) -> Result<()> {
        let (code, reg, request) = match kind {
            InterceptKind::Breakpoint => (INTERCEPT_BREAKPOINT, 0, "breakpoint intercept"),
            InterceptKind::Singlestep => (INTERCEPT_SINGLESTEP, 0, "single-step intercept"),
            InterceptKind::CrWrite(cr) => (INTERCEPT_CR_WRITE, cr, "CR write intercept"),
            InterceptKind::MsrWrite(msr) => (INTERCEPT_MSR_WRITE, msr, "MSR write intercept"),
            InterceptKind::PageAccess => (INTERCEPT_PAGE_ACCESS, 0, "page access intercept"),
        };
        // VMIINTERCEPT: idCpu, uKind, uReg, u32Reserved.
        let mut req = [0u8; 16];
        req[..8].copy_from_slice(&u32_pair(vcpu, code));
        req[8..12].copy_from_slice(&reg.to_le_bytes());
        let (hdr, body) = self.request(msg, &req)?;
        match hdr.rc {
            VERR_INVALID_CPU_ID => Err(Error::NoSuchVcpu(vcpu)),
            VERR_DBGF_ALREADY_ATTACHED => Err(Error::DebuggerAttached),
            VERR_NOT_SUPPORTED => Err(Error::NotSupported { request }),
            rc if rc < 0 => Err(Error::Server { request, rc }),
            _ if !body.is_empty() => Err(Error::Protocol(format!(
                "{} reply of {} bytes",
                request,
                body.len()
            ))),
            _ => Ok(()),
        }
    }

    /// Releases the parked vCPU `vcpu` after its event (`VMI_MSG_EVENT_REPLY`), see [`Reply`]. A
    /// reply that does not fit the event fails with [`Error::InvalidReply`], an emulation the
    /// server cannot perform with [`Error::Server`]; either way the vCPU stays parked, untouched,
    /// and can be replied to again. An emulation reply returns once the vCPU ran the instruction.
    /// A reply while the VM is paused succeeds; the vCPU continues once the VM is resumed.
    pub fn reply_event(&mut self, vcpu: u32, reply: Reply<'_>) -> Result<()> {
        let (flags, action, data): (u32, u32, &[u8]) = match &reply {
            Reply::Continue { reinject: true } => {
                (EVENT_REPLY_F_REINJECT, EVENT_REPLY_CONTINUE, &[])
            }
            Reply::Continue { reinject: false } => (0, EVENT_REPLY_CONTINUE, &[]),
            Reply::Emulate => (0, EVENT_REPLY_EMULATE, &[]),
            Reply::EmulateReadData(data) if (1..=EVENT_REPLY_DATA_MAX).contains(&data.len()) => {
                (0, EVENT_REPLY_EMULATE_READ_DATA, data)
            }
            Reply::EmulateReadData(data) => {
                return Err(Error::Protocol(format!(
                    "emulation read data of {} bytes (1 to {})",
                    data.len(),
                    EVENT_REPLY_DATA_MAX
                )))
            }
            Reply::EmulateInsn(insn) => (0, EVENT_REPLY_EMULATE_INSN, insn),
        };
        // VMIEVENTREPLY: idCpu, fFlags, uAction, cbData, abData.
        let mut req = [0u8; 16 + EVENT_REPLY_DATA_MAX];
        req[..8].copy_from_slice(&u32_pair(vcpu, flags));
        req[8..16].copy_from_slice(&u32_pair(action, data.len() as u32));
        req[16..16 + data.len()].copy_from_slice(data);
        let request = "event reply";
        let (hdr, body) = self.request(MSG_EVENT_REPLY, &req[..16 + data.len()])?;
        match hdr.rc {
            VERR_INVALID_CPU_ID => Err(Error::NoSuchVcpu(vcpu)),
            VERR_INVALID_STATE => Err(Error::NotParked(vcpu)),
            VERR_INVALID_PARAMETER => Err(Error::InvalidReply),
            rc if rc < 0 => Err(Error::Server { request, rc }),
            _ if !body.is_empty() => Err(Error::Protocol(format!(
                "{} reply of {} bytes",
                request,
                body.len()
            ))),
            _ => Ok(()),
        }
    }

    /// Restricts the page holding `gpa` to the `allowed` accesses (`PAGE_ACCESS_*` bits) for the
    /// whole VM (`VMI_MSG_PAGE_ACCESS_SET`); all three bits remove the restriction. vCPUs with the
    /// [`InterceptKind::PageAccess`] Intercept raise an [`EventKind::PageAccess`] on a denied
    /// access. Idempotent; allowed while the VM runs or is paused, also while handling an event.
    /// Write without read, MMIO, ROM and addresses without memory are refused with
    /// [`Error::Server`]; restricting while the VirtualBox debugger is attached with
    /// [`Error::DebuggerAttached`].
    pub fn set_page_access(&mut self, gpa: u64, allowed: u32) -> Result<()> {
        let request = "page access set";
        let (hdr, body) = self.request(MSG_PAGE_ACCESS_SET, &page_access(gpa, allowed))?;
        match hdr.rc {
            VERR_DBGF_ALREADY_ATTACHED => Err(Error::DebuggerAttached),
            VERR_NOT_SUPPORTED => Err(Error::NotSupported { request }),
            rc if rc < 0 => Err(Error::Server { request, rc }),
            _ if !body.is_empty() => Err(Error::Protocol(format!(
                "{} reply of {} bytes",
                request,
                body.len()
            ))),
            _ => Ok(()),
        }
    }

    /// The accesses allowed on the page holding `gpa` (`VMI_MSG_PAGE_ACCESS_GET`): all three
    /// `PAGE_ACCESS_*` bits if it was never restricted.
    pub fn get_page_access(&mut self, gpa: u64) -> Result<u32> {
        let request = "page access get";
        let (hdr, body) = self.request(MSG_PAGE_ACCESS_GET, &page_access(gpa, 0))?;
        match hdr.rc {
            VERR_NOT_SUPPORTED => Err(Error::NotSupported { request }),
            rc if rc < 0 => Err(Error::Server { request, rc }),
            _ => Ok(u32::from_le_bytes(body.try_into().map_err(|_| {
                Error::Protocol(format!("{} reply of {} bytes", request, body.len()))
            })?)),
        }
    }

    /// Returns the oldest pending [`Event`], or `None` after `timeout` elapsed. A zero timeout
    /// polls without waiting. Events received while requests await replies are queued in order.
    pub fn wait_event(&mut self, timeout: Duration) -> Result<Option<Event>> {
        if let Some(event) = self.events.pop_front() {
            return Ok(Some(event));
        }
        let deadline = Instant::now().checked_add(timeout);
        loop {
            let remaining = deadline.map(|end| end.saturating_duration_since(Instant::now()));
            let ms = match remaining {
                Some(duration) => duration
                    .as_millis()
                    .saturating_add(u128::from(duration.subsec_nanos() % 1_000_000 != 0)),
                None => i32::MAX as u128,
            };
            let mut fds = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut fds, 1, ms.min(i32::MAX as u128) as i32) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }
            if rc == 0 {
                if deadline.is_some_and(|end| Instant::now() >= end) {
                    return Ok(None);
                }
                continue;
            }
            let hdr = self.recv()?;
            return Ok(Some(self.decode_event(hdr)?));
        }
    }

    /// Decodes a server-to-client `VMIEVENT`; rejects replies or malformed events.
    fn decode_event(&self, hdr: Header) -> Result<Event> {
        if hdr.kind != MSG_EVENT || hdr.id != 0 || hdr.flags != 0 || hdr.rc != 0 {
            return Err(Error::Protocol(format!("unexpected event {:?}", hdr)));
        }
        let body = self.body(hdr);
        if body.len() != 40 {
            return Err(Error::Protocol(format!(
                "event body of {} bytes",
                body.len()
            )));
        }
        let u32_at = |o: usize| u32::from_le_bytes(body[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(body[o..o + 8].try_into().unwrap());
        let (vcpu, kind, gpa, insn_len) = (u32_at(0), u32_at(4), u64_at(8), u32_at(16));
        let (reg, old, new) = (u32_at(20), u64_at(24), u64_at(32));
        let kind = match (kind, gpa, insn_len, reg, old, new) {
            (INTERCEPT_BREAKPOINT, gpa, len, 0, 0, 0) => {
                EventKind::Breakpoint { gpa, insn_len: len }
            }
            (INTERCEPT_SINGLESTEP, gpa, 0, 0, 0, 0) => EventKind::Singlestep { gpa },
            (INTERCEPT_CR_WRITE, 0, 0, cr, old, new) => EventKind::CrWrite { cr, old, new },
            (INTERCEPT_MSR_WRITE, 0, 0, msr, old, new) => EventKind::MsrWrite { msr, old, new },
            (
                INTERCEPT_PAGE_ACCESS,
                gpa,
                0,
                access @ (PAGE_ACCESS_R | PAGE_ACCESS_W | PAGE_ACCESS_X),
                gva,
                0,
            ) => EventKind::PageAccess { gpa, gva, access },
            _ => return Err(Error::Protocol(format!("invalid event body {:02x?}", body))),
        };
        Ok(Event { vcpu, kind })
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

        loop {
            let reply = self.recv()?;
            if reply.kind == MSG_EVENT {
                let event = self.decode_event(reply)?;
                self.events.push_back(event);
                continue;
            }
            if reply.flags != MSG_F_REPLY || reply.id != id || reply.kind != kind {
                return Err(Error::Protocol(format!(
                    "unexpected reply {:?} to request {} type {}",
                    reply, id, kind
                )));
            }
            return Ok((reply, self.body(reply)));
        }
    }

    /// Receives one message into the reusable buffer.
    fn recv(&mut self) -> Result<Header> {
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
        Ok(hdr)
    }

    fn body(&self, hdr: Header) -> &[u8] {
        &self.buf[HDR_SIZE..hdr.size as usize]
    }
}

/// Two `u32`: the `VMIHELLO` and `VMIVCPUREQ` (vCPU, reserved 0) bodies, and field pairs of
/// `VMIINTERCEPT` and `VMIEVENTREPLY`.
fn u32_pair(first: u32, second: u32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&first.to_le_bytes());
    b[4..8].copy_from_slice(&second.to_le_bytes());
    b
}

/// `VMIPAGEACCESS`: GCPhys, fAccess, reserved 0.
fn page_access(gpa: u64, access: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&gpa.to_le_bytes());
    b[8..12].copy_from_slice(&access.to_le_bytes());
    b
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

    #[test]
    fn registers_layout_matches_vmix86regs() {
        let regs = X86Registers {
            rax: 1,
            rcx: 2,
            r15: 16,
            rip: 0x11,
            rflags: 0x202,
            cr0: 0x13,
            efer: 0x17,
            apic_base: 0x1d,
            es: Segment {
                base: 0xe5,
                limit: 0xe4,
                selector: 0xe2,
            },
            cs: Segment {
                base: 0xc5,
                limit: 0xc4,
                selector: 0x10,
            },
            tr: Segment {
                base: 0x75,
                limit: 0x74,
                selector: 0x40,
            },
            gdtr: TableRegister {
                base: 0x9d,
                limit: 0x7f,
            },
            idtr: TableRegister {
                base: 0x1d7,
                limit: 0xfff,
            },
            ..Default::default()
        };
        let b = regs.encode();
        let u64_at = |off: usize| u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
        // offsets of VMIX86REGS in VBoxVMI-protocol.md
        assert_eq!(u64_at(0), 1);
        assert_eq!(u64_at(8), 2);
        assert_eq!(u64_at(120), 16);
        assert_eq!(u64_at(128), 0x11);
        assert_eq!(u64_at(136), 0x202);
        assert_eq!(u64_at(144), 0x13);
        assert_eq!(u64_at(176), 0x17);
        assert_eq!(u64_at(224), 0x1d);
        assert_eq!(
            &b[232..248],
            &[0xe5, 0, 0, 0, 0, 0, 0, 0, 0xe4, 0, 0, 0, 0xe2, 0, 0, 0]
        );
        assert_eq!(u64_at(248), 0xc5);
        assert_eq!(&b[256..260], &[0xc4, 0, 0, 0]);
        assert_eq!(&b[260..262], &[0x10, 0]);
        assert_eq!(u64_at(344), 0x75);
        assert_eq!(u64_at(360), 0x9d);
        assert_eq!(&b[368..376], &[0x7f, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(u64_at(376), 0x1d7);
        assert_eq!(&b[384..392], &[0xff, 0x0f, 0, 0, 0, 0, 0, 0]);
        assert_eq!(X86Registers::decode(&b).unwrap(), regs);
        assert!(X86Registers::decode(&b[1..]).is_err());
    }

    fn write_test_pair() -> (Client, OwnedFd) {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        (
            Client {
                fd: unsafe { OwnedFd::from_raw_fd(fds[0]) },
                next_id: 1,
                buf: vec![0; MSG_SIZE_MAX],
                events: VecDeque::new(),
            },
            unsafe { OwnedFd::from_raw_fd(fds[1]) },
        )
    }

    fn write_test_request(fd: &OwnedFd) -> (Header, Vec<u8>) {
        test_request(fd, MSG_PHYS_WRITE)
    }

    /// Receives one request of type `kind` on the fake server side.
    fn test_request(fd: &OwnedFd, kind: u16) -> (Header, Vec<u8>) {
        let mut packet = vec![0; MSG_SIZE_MAX];
        let n = unsafe { libc::recv(fd.as_raw_fd(), packet.as_mut_ptr().cast(), packet.len(), 0) };
        assert!(n >= HDR_SIZE as isize);
        packet.truncate(n as usize);
        let hdr = Header::decode(&packet);
        assert_eq!(hdr.size as usize, packet.len());
        assert_eq!(hdr.kind, kind);
        assert_eq!(hdr.flags, 0);
        (hdr, packet[HDR_SIZE..].to_vec())
    }

    /// Sends one message from the fake server side.
    fn test_send(fd: &OwnedFd, id: u32, kind: u16, flags: u16, rc: i32, body: &[u8]) {
        let mut packet = Header {
            size: (HDR_SIZE + body.len()) as u32,
            id,
            kind,
            flags,
            rc,
        }
        .encode()
        .to_vec();
        packet.extend_from_slice(body);
        assert_eq!(
            unsafe {
                libc::send(
                    fd.as_raw_fd(),
                    packet.as_ptr().cast(),
                    packet.len(),
                    libc::MSG_NOSIGNAL,
                )
            },
            packet.len() as isize
        );
    }

    fn write_test_reply(fd: &OwnedFd, request: Header, rc: i32, statuses: &[i32]) {
        let body: Vec<u8> = statuses.iter().flat_map(|s| s.to_le_bytes()).collect();
        test_send(fd, request.id, request.kind, MSG_F_REPLY, rc, &body);
    }

    #[test]
    fn version_1_greeting_is_refused() {
        let (client, server) = write_test_pair();
        let worker = std::thread::spawn(move || {
            test_send(&server, 0, MSG_HELLO, 0, 0, &u32_pair(MAGIC, 1));
            server
        });
        let err = Client::handshake(client.fd).err().unwrap();
        assert!(matches!(
            err,
            Error::VersionMismatch {
                server: 1,
                client: 2
            }
        ));
        worker.join().unwrap();
    }

    #[test]
    fn intercept_and_event_reply_layout_matches_contract() {
        let (mut client, server) = write_test_pair();
        let worker = std::thread::spawn(move || {
            // VMI_MSG_INTERCEPT_SET, _CLEAR (idCpu, uKind, uReg, reserved), VMI_MSG_EVENT_REPLY
            // (idCpu, fFlags, uAction, cbData).
            for (kind, body) in [
                (0x0a, &[3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..]),
                (0x0b, &[3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                (0x0a, &[1, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]),
                (
                    0x0b,
                    &[1, 0, 0, 0, 4, 0, 0, 0, 0x80, 0, 0, 0xc0, 0, 0, 0, 0],
                ),
                (0x0c, &[1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                (0x0c, &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            ] {
                let (hdr, got) = test_request(&server, kind);
                assert_eq!(got, body);
                write_test_reply(&server, hdr, 0, &[]);
            }
        });
        client.set_intercept(3, InterceptKind::Breakpoint).unwrap();
        client
            .clear_intercept(3, InterceptKind::Singlestep)
            .unwrap();
        client.set_intercept(1, InterceptKind::CrWrite(4)).unwrap();
        client
            .clear_intercept(1, InterceptKind::MsrWrite(0xc000_0080))
            .unwrap();
        client
            .reply_event(1, Reply::Continue { reinject: true })
            .unwrap();
        client
            .reply_event(1, Reply::Continue { reinject: false })
            .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn emulation_reply_layout_matches_contract() {
        let (mut client, server) = write_test_pair();
        let insn: [u8; 16] = core::array::from_fn(|i| 0x90 + i as u8);
        let worker = std::thread::spawn(move || {
            // uAction 1 EMULATE, 2 EMULATE_READ_DATA, 3 EMULATE_INSN; abData after 16 bytes.
            let mut expected = vec![
                vec![2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
                vec![
                    2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xaa, 0xbb, 0xcc,
                ],
                [
                    vec![0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 16, 0, 0, 0],
                    insn.to_vec(),
                ]
                .concat(),
            ];
            let mut max = vec![2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1, 0, 0];
            max.extend([0x5a; 256]);
            expected.push(max);
            for body in expected {
                let (hdr, got) = test_request(&server, 0x0c);
                assert_eq!(got, body);
                write_test_reply(&server, hdr, 0, &[]);
            }
            // IEM could not emulate: the vCPU stays parked, the status comes back.
            let (hdr, _) = test_request(&server, 0x0c);
            write_test_reply(&server, hdr, -5391, &[]);
        });
        client.reply_event(2, Reply::Emulate).unwrap();
        client
            .reply_event(2, Reply::EmulateReadData(&[0xaa, 0xbb, 0xcc]))
            .unwrap();
        client.reply_event(0, Reply::EmulateInsn(insn)).unwrap();
        // Refused without a request: the server's next message must be the 256-byte reply.
        assert!(matches!(
            client.reply_event(2, Reply::EmulateReadData(&[])),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            client.reply_event(2, Reply::EmulateReadData(&[0x5a; 257])),
            Err(Error::Protocol(_))
        ));
        client
            .reply_event(2, Reply::EmulateReadData(&[0x5a; 256]))
            .unwrap();
        assert!(matches!(
            client.reply_event(2, Reply::Emulate),
            Err(Error::Server {
                request: "event reply",
                rc: -5391
            })
        ));
        worker.join().unwrap();
    }

    #[test]
    fn intercept_and_event_reply_errors_map_to_variants() {
        let (mut client, server) = write_test_pair();
        let worker = std::thread::spawn(move || {
            for (kind, rc) in [
                (0x0a, -1201),
                (0x0a, -37),
                (0x0a, -1018),
                (0x0b, -1018),
                (0x0c, -79),
                (0x0c, -2),
                (0x0c, -1018),
                (0x0c, -5),
            ] {
                let (hdr, _) = test_request(&server, kind);
                write_test_reply(&server, hdr, rc, &[]);
            }
        });
        use InterceptKind::*;
        assert!(matches!(
            client.set_intercept(0, Breakpoint),
            Err(Error::DebuggerAttached)
        ));
        assert!(matches!(
            client.set_intercept(0, Singlestep),
            Err(Error::NotSupported {
                request: "single-step intercept"
            })
        ));
        assert!(matches!(
            client.set_intercept(7, Breakpoint),
            Err(Error::NoSuchVcpu(7))
        ));
        assert!(matches!(
            client.clear_intercept(8, Breakpoint),
            Err(Error::NoSuchVcpu(8))
        ));
        let cont = Reply::Continue { reinject: false };
        assert!(matches!(
            client.reply_event(2, cont),
            Err(Error::NotParked(2))
        ));
        assert!(matches!(
            client.reply_event(2, Reply::Continue { reinject: true }),
            Err(Error::InvalidReply)
        ));
        assert!(matches!(
            client.reply_event(9, cont),
            Err(Error::NoSuchVcpu(9))
        ));
        assert!(matches!(
            client.reply_event(2, cont),
            Err(Error::Server {
                request: "event reply",
                rc: -5
            })
        ));
        worker.join().unwrap();
    }

    #[test]
    fn page_access_request_layout_matches_contract() {
        let (mut client, server) = write_test_pair();
        let worker = std::thread::spawn(move || {
            // VMI_MSG_PAGE_ACCESS_SET / _GET: VMIPAGEACCESS (GCPhys, fAccess, reserved).
            let (hdr, body) = test_request(&server, 0x0e);
            assert_eq!(body, [0x34, 0x12, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0]);
            write_test_reply(&server, hdr, 0, &[]);
            let (hdr, body) = test_request(&server, 0x0f);
            assert_eq!(body, [0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            write_test_reply(&server, hdr, 0, &[3]);
            for rc in [-1201, -37, -1618] {
                let (hdr, _) = test_request(&server, 0x0e);
                write_test_reply(&server, hdr, rc, &[]);
            }
        });
        client
            .set_page_access(0x1_0000_1234, PAGE_ACCESS_R | PAGE_ACCESS_X)
            .unwrap();
        assert_eq!(
            client.get_page_access(0x2000).unwrap(),
            PAGE_ACCESS_R | PAGE_ACCESS_W
        );
        assert!(matches!(
            client.set_page_access(0, PAGE_ACCESS_R),
            Err(Error::DebuggerAttached)
        ));
        assert!(matches!(
            client.set_page_access(0, PAGE_ACCESS_X),
            Err(Error::NotSupported {
                request: "page access set"
            })
        ));
        assert!(matches!(
            client.set_page_access(0xfee0_0000, PAGE_ACCESS_R),
            Err(Error::Server {
                request: "page access set",
                rc: -1618
            })
        ));
        worker.join().unwrap();
    }

    /// A `VMIEVENT` body at the contract's offsets.
    fn event_body(
        vcpu: u32,
        kind: u32,
        gpa: u64,
        insn_len: u32,
        reg: u32,
        old: u64,
        new: u64,
    ) -> [u8; 40] {
        let mut b = [0u8; 40];
        b[0..4].copy_from_slice(&vcpu.to_le_bytes());
        b[4..8].copy_from_slice(&kind.to_le_bytes());
        b[8..16].copy_from_slice(&gpa.to_le_bytes());
        b[16..20].copy_from_slice(&insn_len.to_le_bytes());
        b[20..24].copy_from_slice(&reg.to_le_bytes());
        b[24..32].copy_from_slice(&old.to_le_bytes());
        b[32..40].copy_from_slice(&new.to_le_bytes());
        b
    }

    fn send_event(fd: &OwnedFd, vcpu: u32, kind: u32, gpa: u64, insn_len: u32) {
        test_send(
            fd,
            0,
            0x0d,
            0,
            0,
            &event_body(vcpu, kind, gpa, insn_len, 0, 0, 0),
        );
    }

    #[test]
    fn page_access_intercept_and_event_match_contract() {
        let (mut client, server) = write_test_pair();
        let worker = std::thread::spawn(move || {
            let (hdr, body) = test_request(&server, 0x0a);
            assert_eq!(body, [2, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            write_test_reply(&server, hdr, 0, &[]);
            // GCPhys, cbInstr 0, uReg = access, GCPtr in the uOld slot, uNew 0.
            let write = event_body(2, 5, 0x1_2345, 0, 2, 0xffff_8000_0001_2345, 0);
            test_send(&server, 0, 0x0d, 0, 0, &write);
            let exec_no_gva = event_body(0, 5, 0x3000, 0, 4, 0, 0);
            test_send(&server, 0, 0x0d, 0, 0, &exec_no_gva);
            // Two accesses at once is not a page-access event.
            let bad = event_body(0, 5, 0x3000, 0, 3, 0, 0);
            test_send(&server, 0, 0x0d, 0, 0, &bad);
            server
        });
        client.set_intercept(2, InterceptKind::PageAccess).unwrap();
        assert_eq!(
            client.wait_event(Duration::from_secs(10)).unwrap(),
            Some(Event {
                vcpu: 2,
                kind: EventKind::PageAccess {
                    gpa: 0x1_2345,
                    gva: 0xffff_8000_0001_2345,
                    access: PAGE_ACCESS_W
                }
            })
        );
        assert_eq!(
            client.wait_event(Duration::from_secs(10)).unwrap(),
            Some(Event {
                vcpu: 0,
                kind: EventKind::PageAccess {
                    gpa: 0x3000,
                    gva: 0,
                    access: PAGE_ACCESS_X
                }
            })
        );
        assert!(matches!(
            client.wait_event(Duration::from_secs(10)),
            Err(Error::Protocol(_))
        ));
        worker.join().unwrap();
    }

    #[test]
    fn cr_and_msr_events_decode_and_cr_reinjection_is_refused() {
        let (mut client, server) = write_test_pair();
        let worker = std::thread::spawn(move || {
            let cr = event_body(1, 3, 0, 0, 3, 0x1000, 0x2000);
            test_send(&server, 0, 0x0d, 0, 0, &cr);
            let msr = event_body(0, 4, 0, 0, 0xc000_0080, 0xd01, 0x501);
            test_send(&server, 0, 0x0d, 0, 0, &msr);
            let (hdr, body) = test_request(&server, 0x0c);
            assert_eq!(body, [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            write_test_reply(&server, hdr, -2, &[]);
            server
        });
        assert_eq!(
            client.wait_event(Duration::from_secs(10)).unwrap(),
            Some(Event {
                vcpu: 1,
                kind: EventKind::CrWrite {
                    cr: 3,
                    old: 0x1000,
                    new: 0x2000
                }
            })
        );
        assert_eq!(
            client.wait_event(Duration::from_secs(10)).unwrap(),
            Some(Event {
                vcpu: 0,
                kind: EventKind::MsrWrite {
                    msr: 0xc000_0080,
                    old: 0xd01,
                    new: 0x501
                }
            })
        );
        assert!(matches!(
            client.reply_event(1, Reply::Continue { reinject: true }),
            Err(Error::InvalidReply)
        ));
        worker.join().unwrap();
    }

    #[test]
    fn events_received_with_replies_are_queued_then_waited_for_in_order() {
        let (mut client, server) = write_test_pair();
        let worker = std::thread::spawn(move || {
            let (hdr, _) = test_request(&server, 0x0a);
            send_event(&server, 0, 1, 0x1_2345_6789, 1);
            send_event(&server, 1, 2, 0xfedc_ba98_7654_3210, 0);
            write_test_reply(&server, hdr, 0, &[]);
            let (hdr, _) = test_request(&server, MSG_VCPU_COUNT);
            send_event(&server, 2, 1, 0x4000, 3);
            write_test_reply(&server, hdr, 0, &[3]);
            std::thread::sleep(Duration::from_millis(50));
            send_event(&server, 0, 2, 0x5000, 0);
            server
        });
        client.set_intercept(0, InterceptKind::Breakpoint).unwrap();
        assert_eq!(client.vcpu_count().unwrap(), 3);
        let event = |vcpu, kind| Some(Event { vcpu, kind });
        assert_eq!(
            client.wait_event(Duration::ZERO).unwrap(),
            event(
                0,
                EventKind::Breakpoint {
                    gpa: 0x1_2345_6789,
                    insn_len: 1
                }
            )
        );
        assert_eq!(
            client.wait_event(Duration::ZERO).unwrap(),
            event(
                1,
                EventKind::Singlestep {
                    gpa: 0xfedc_ba98_7654_3210
                }
            )
        );
        assert_eq!(
            client.wait_event(Duration::ZERO).unwrap(),
            event(
                2,
                EventKind::Breakpoint {
                    gpa: 0x4000,
                    insn_len: 3
                }
            )
        );
        assert_eq!(
            client.wait_event(Duration::from_secs(10)).unwrap(),
            event(0, EventKind::Singlestep { gpa: 0x5000 })
        );
        let _server = worker.join().unwrap();
        assert_eq!(client.wait_event(Duration::ZERO).unwrap(), None);
    }

    #[test]
    fn wait_event_times_out_with_none() {
        let (mut client, _server) = write_test_pair();
        let start = std::time::Instant::now();
        assert_eq!(client.wait_event(Duration::from_millis(50)).unwrap(), None);
        assert!(start.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn messages_other_than_replies_and_events_are_protocol_errors() {
        let (mut client, server) = write_test_pair();
        let worker = std::thread::spawn(move || {
            let (hdr, _) = test_request(&server, MSG_VCPU_COUNT);
            // An event must have idReq 0.
            test_send(
                &server,
                hdr.id,
                0x0d,
                0,
                0,
                &event_body(0, 1, 0, 1, 0, 0, 0),
            );
            test_send(&server, 9, MSG_PAUSE, MSG_F_REPLY, 0, &[]);
            server
        });
        assert!(matches!(client.vcpu_count(), Err(Error::Protocol(_))));
        assert!(matches!(
            client.wait_event(Duration::from_secs(10)),
            Err(Error::Protocol(_))
        ));
        worker.join().unwrap();
    }

    #[test]
    fn write_physical_descriptors_precede_contiguous_data_and_status_is_per_page() {
        let (mut client, server) = write_test_pair();
        let worker = std::thread::spawn(move || {
            let (hdr, body) = write_test_request(&server);
            let mut expected = Vec::new();
            expected.extend_from_slice(&2u32.to_le_bytes());
            expected.extend_from_slice(&0xfffu64.to_le_bytes());
            expected.extend_from_slice(&2u32.to_le_bytes());
            expected.extend_from_slice(&0u32.to_le_bytes());
            expected.extend_from_slice(&0x9000u64.to_le_bytes());
            expected.extend_from_slice(&3u32.to_le_bytes());
            expected.extend_from_slice(&0u32.to_le_bytes());
            expected.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
            assert_eq!(body, expected);
            write_test_reply(&server, hdr, 0, &[0, -1618, -1605]);
        });
        let mut status = vec![77];
        client
            .write_physical(
                &[
                    (0xfff, &[0xaa, 0xbb][..]),
                    (0x9000, &[0xcc, 0xdd, 0xee][..]),
                    (0, &[]),
                ],
                &mut status,
            )
            .unwrap();
        assert_eq!(status, [77, 0, -1618, -1605]);
        worker.join().unwrap();
    }

    #[test]
    fn write_physical_splits_long_range_on_request_limit() {
        let (mut client, server) = write_test_pair();
        let data: Vec<u8> = (0..20 * PAGE_SIZE as usize).map(|i| i as u8).collect();
        let expected = data.clone();
        let worker = std::thread::spawn(move || {
            for (start_page, pages) in [(0, 15), (15, 5)] {
                let (hdr, body) = write_test_request(&server);
                assert_eq!(u32::from_le_bytes(body[0..4].try_into().unwrap()), 1);
                assert_eq!(
                    u64::from_le_bytes(body[4..12].try_into().unwrap()),
                    start_page as u64 * PAGE_SIZE
                );
                assert_eq!(
                    u32::from_le_bytes(body[12..16].try_into().unwrap()),
                    pages * PAGE_SIZE as u32
                );
                assert_eq!(&body[16..20], &[0; 4]);
                assert_eq!(
                    &body[20..],
                    &expected[start_page * PAGE_SIZE as usize
                        ..(start_page + pages as usize) * PAGE_SIZE as usize]
                );
                assert!(hdr.size as usize <= MSG_SIZE_MAX);
                write_test_reply(&server, hdr, 0, &vec![start_page as i32; pages as usize]);
            }
        });
        let mut status = Vec::new();
        client.write_physical(&[(0, &data)], &mut status).unwrap();
        assert_eq!(status, [vec![0; 15], vec![15; 5]].concat());
        worker.join().unwrap();
    }

    #[test]
    fn write_physical_splits_many_ranges_before_descriptors_exceed_limit() {
        let (mut client, server) = write_test_pair();
        let data = [0x5a];
        let ranges: Vec<_> = (0..4000).map(|i| (i * PAGE_SIZE, &data[..])).collect();
        let worker = std::thread::spawn(move || {
            for (first, count) in [(0, 3853), (3853, 147)] {
                let (hdr, body) = write_test_request(&server);
                assert_eq!(hdr.size as usize, HDR_SIZE + 4 + count * (RANGE_SIZE + 1));
                assert_eq!(
                    u32::from_le_bytes(body[0..4].try_into().unwrap()),
                    count as u32
                );
                for j in 0..count {
                    let descriptor = &body[4 + j * RANGE_SIZE..4 + (j + 1) * RANGE_SIZE];
                    assert_eq!(
                        u64::from_le_bytes(descriptor[0..8].try_into().unwrap()),
                        (first + j) as u64 * PAGE_SIZE
                    );
                    assert_eq!(&descriptor[8..16], &[1, 0, 0, 0, 0, 0, 0, 0]);
                }
                assert_eq!(&body[4 + count * RANGE_SIZE..], vec![0x5a; count]);
                write_test_reply(&server, hdr, 0, &vec![0; count]);
            }
        });
        let mut status = Vec::new();
        client.write_physical(&ranges, &mut status).unwrap();
        assert_eq!(status, vec![0; 4000]);
        worker.join().unwrap();
    }

    #[test]
    fn write_physical_rejects_wrapping_range_without_sending() {
        let (mut client, _server) = write_test_pair();
        let mut status = vec![9];
        let result = client.write_physical(&[(0, &[1]), (u64::MAX, &[2, 3])], &mut status);
        assert!(matches!(result, Err(Error::Protocol(_))));
        assert_eq!(client.next_id, 1);
        assert_eq!(status, [9]);
    }

    #[test]
    fn write_physical_checks_reply_length_and_retains_completed_statuses() {
        let (mut client, server) = write_test_pair();
        let data = vec![0x42; 20 * PAGE_SIZE as usize];
        let worker = std::thread::spawn(move || {
            let (first, _) = write_test_request(&server);
            write_test_reply(&server, first, 0, &[0; 15]);
            let (second, _) = write_test_request(&server);
            write_test_reply(&server, second, 0, &[0; 4]);
            let (third, _) = write_test_request(&server);
            write_test_reply(&server, third, VERR_INVALID_PARAMETER, &[]);
        });
        let mut status = vec![7];
        let err = client
            .write_physical(&[(0, &data)], &mut status)
            .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
        assert_eq!(status, [vec![7], vec![0; 15]].concat());
        let err = client
            .write_physical(&[(0, &[1])], &mut status)
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Server {
                request: "physical write",
                rc: VERR_INVALID_PARAMETER
            }
        ));
        assert_eq!(status, [vec![7], vec![0; 15]].concat());
        worker.join().unwrap();
    }
}
