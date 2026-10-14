//! Waits for one intercepted int3, single-step, CR write, MSR write or page-access event on a vCPU
//! (default 0), then releases it. Breakpoint mode needs the guest to execute an int3; clearing the
//! Intercept and reinjecting #BP lets the guest handle it normally. CR and MSR writes proceed
//! unchanged. Page mode denies every access to the page at a guest-physical address, then lifts the
//! restriction and retries the access.
//! Usage: events <socket path> <breakpoint|singlestep|cr <0|3|4>|msr <index>|page <gpa>> [<vcpu>]

use std::convert::TryFrom;
use std::error::Error;
use std::time::Duration;
use vboxvmi::{
    Client, EventKind, InterceptKind, Reply, PAGE_ACCESS_R, PAGE_ACCESS_W, PAGE_ACCESS_X,
};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        return Err(format!(
            "usage: {} <socket path> <breakpoint|singlestep|cr <0|3|4>|msr <index>|page <gpa>> [<vcpu>]",
            args[0]
        )
        .into());
    }
    let num = |s: &str| match s.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => s.parse(),
    };
    let mut page = None;
    let (kind, rest) = match args[2].as_str() {
        "breakpoint" => (InterceptKind::Breakpoint, 3),
        "singlestep" => (InterceptKind::Singlestep, 3),
        "cr" => (
            InterceptKind::CrWrite(args.get(3).ok_or("cr needs 0, 3 or 4")?.parse()?),
            4,
        ),
        "msr" => {
            let index = num(args.get(3).ok_or("msr needs an index")?)?;
            (InterceptKind::MsrWrite(u32::try_from(index)?), 4)
        }
        "page" => {
            page = Some(num(args
                .get(3)
                .ok_or("page needs a guest-physical address")?)?);
            (InterceptKind::PageAccess, 4)
        }
        _ => return Err("kind must be breakpoint, singlestep, cr, msr or page".into()),
    };
    let vcpu = args.get(rest).map_or(Ok(0), |s| s.parse())?;
    let mut client = Client::connect(&args[1])?;
    client.set_intercept(vcpu, kind)?;
    if let Some(gpa) = page {
        client.set_page_access(gpa, 0)?;
    }
    let event = loop {
        if let Some(event) = client.wait_event(Duration::from_secs(5))? {
            break event;
        }
    };
    match event.kind {
        EventKind::CrWrite { cr, old, new } => {
            println!("vCPU {} CR{} {:#x} -> {:#x}", event.vcpu, cr, old, new)
        }
        EventKind::MsrWrite { msr, old, new } => {
            println!(
                "vCPU {} MSR {:#x} {:#x} -> {:#x}",
                event.vcpu, msr, old, new
            )
        }
        EventKind::PageAccess { gpa, gva, access } => {
            println!(
                "vCPU {} access {} at {:#x} (linear {:#x})",
                event.vcpu, access, gpa, gva
            )
        }
        _ => println!("{:?}", event),
    }
    client.clear_intercept(vcpu, kind)?;
    if let Some(gpa) = page {
        client.set_page_access(gpa, PAGE_ACCESS_R | PAGE_ACCESS_W | PAGE_ACCESS_X)?;
    }
    let reinject = kind == InterceptKind::Breakpoint;
    client.reply_event(event.vcpu, Reply::Continue { reinject })?;
    Ok(())
}
