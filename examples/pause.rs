//! Prints the vCPU count, then pauses the VM for some seconds (default 5) and resumes it.
//! Usage: pause <socket path> [<seconds>]

use std::error::Error;
use std::thread::sleep;
use std::time::Duration;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Err(format!("usage: {} <socket path> [<seconds>]", args[0]).into());
    }
    let seconds = args.get(2).map_or(Ok(5), |s| s.parse())?;
    let mut client = vboxvmi::Client::connect(&args[1])?;
    println!("{} vCPU(s)", client.vcpu_count()?);
    client.pause()?;
    println!("paused for {}s", seconds);
    sleep(Duration::from_secs(seconds));
    client.resume()?;
    println!("resumed");
    Ok(())
}
