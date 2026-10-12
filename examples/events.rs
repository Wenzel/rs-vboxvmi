//! Waits for one intercepted int3 or single-step event on a vCPU (default 0), then releases it.
//! Breakpoint mode needs the guest to execute an int3; clearing the Intercept and reinjecting #BP
//! lets the guest handle it normally.
//! Usage: events <socket path> <breakpoint|singlestep> [<vcpu>]

use std::error::Error;
use std::time::Duration;
use vboxvmi::{Client, InterceptKind};

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
            "usage: {} <socket path> <breakpoint|singlestep> [<vcpu>]",
            args[0]
        )
        .into());
    }
    let kind = match args[2].as_str() {
        "breakpoint" => InterceptKind::Breakpoint,
        "singlestep" => InterceptKind::Singlestep,
        _ => return Err("kind must be breakpoint or singlestep".into()),
    };
    let vcpu = args.get(3).map_or(Ok(0), |s| s.parse())?;
    let mut client = Client::connect(&args[1])?;
    client.set_intercept(vcpu, kind)?;
    let event = loop {
        if let Some(event) = client.wait_event(Duration::from_secs(5))? {
            break event;
        }
    };
    println!("{:?}", event);
    client.clear_intercept(vcpu, kind)?;
    client.reply_event(event.vcpu, kind == InterceptKind::Breakpoint)?;
    Ok(())
}
