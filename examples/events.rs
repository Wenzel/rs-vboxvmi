//! Waits for one intercepted int3, single-step, CR write or MSR write event on a vCPU (default 0),
//! then releases it. Breakpoint mode needs the guest to execute an int3; clearing the Intercept
//! and reinjecting #BP lets the guest handle it normally. CR and MSR writes proceed unchanged.
//! Usage: events <socket path> <breakpoint|singlestep|cr <0|3|4>|msr <index>> [<vcpu>]

use std::error::Error;
use std::time::Duration;
use vboxvmi::{Client, EventKind, InterceptKind};

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
            "usage: {} <socket path> <breakpoint|singlestep|cr <0|3|4>|msr <index>> [<vcpu>]",
            args[0]
        )
        .into());
    }
    let (kind, rest) = match args[2].as_str() {
        "breakpoint" => (InterceptKind::Breakpoint, 3),
        "singlestep" => (InterceptKind::Singlestep, 3),
        "cr" => (
            InterceptKind::CrWrite(args.get(3).ok_or("cr needs 0, 3 or 4")?.parse()?),
            4,
        ),
        "msr" => {
            let index = args.get(3).ok_or("msr needs an index")?;
            let index = match index.strip_prefix("0x") {
                Some(hex) => u32::from_str_radix(hex, 16)?,
                None => index.parse()?,
            };
            (InterceptKind::MsrWrite(index), 4)
        }
        _ => return Err("kind must be breakpoint, singlestep, cr or msr".into()),
    };
    let vcpu = args.get(rest).map_or(Ok(0), |s| s.parse())?;
    let mut client = Client::connect(&args[1])?;
    client.set_intercept(vcpu, kind)?;
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
        _ => println!("{:?}", event),
    }
    client.clear_intercept(vcpu, kind)?;
    client.reply_event(event.vcpu, kind == InterceptKind::Breakpoint)?;
    Ok(())
}
