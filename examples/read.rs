//! Prints the guest's RAM ranges, then reads one page at each address in a single batched request
//! and prints each page's status and first bytes.
//! Usage: read <socket path> [<hex address>...]

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
        return Err(format!("usage: {} <socket path> [<hex address>...]", args[0]).into());
    }
    let mut client = vboxvmi::Client::connect(&args[1])?;
    for r in client.ram_ranges()? {
        println!("RAM {:#014x}-{:#014x}", r.start, r.end - 1);
    }
    let addrs = args[2..]
        .iter()
        .map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16))
        .collect::<Result<Vec<_>, _>>()?;
    let mut pages = vec![[0u8; vboxvmi::PAGE_SIZE as usize]; addrs.len()];
    let mut ranges: Vec<(u64, &mut [u8])> = addrs
        .iter()
        .zip(pages.iter_mut())
        .map(|(&a, p)| (a & !(vboxvmi::PAGE_SIZE - 1), &mut p[..]))
        .collect();
    let mut status = Vec::new();
    client.read_physical(&mut ranges, &mut status)?;
    for ((addr, page), rc) in ranges.iter().zip(status) {
        println!("{:#014x} status {:5} {:02x?}", addr, rc, &page[..16]);
    }
    Ok(())
}
