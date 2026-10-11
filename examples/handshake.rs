//! Connects to a VM's VBoxVMI socket and completes the handshake.
//! Usage: handshake <socket path>

use std::error::Error;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        return Err(format!("usage: {} <socket path>", args[0]).into());
    }
    let _client = vboxvmi::Client::connect(&args[1])?;
    println!(
        "handshake with {} done: VBoxVMI protocol version {}",
        args[1],
        vboxvmi::VERSION
    );
    Ok(())
}
