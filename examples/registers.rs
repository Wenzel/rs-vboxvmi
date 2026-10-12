//! Prints the registers of a vCPU (default 0), then writes them back unchanged, which the server
//! accepts without touching any register.
//! Usage: registers <socket path> [<vcpu>]

use std::error::Error;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Err(format!("usage: {} <socket path> [<vcpu>]", args[0]).into());
    }
    let vcpu = args.get(2).map_or(Ok(0), |s| s.parse())?;
    let mut client = vboxvmi::Client::connect(&args[1])?;
    let regs = client.read_registers(vcpu)?;
    println!("{:#x?}", regs);
    client.write_registers(vcpu, &regs)?;
    println!("written back");
    Ok(())
}
