//! The stamper's signing tool. It never prints a key.
//!
//!   stamper keygen  --network testnet --key /data/stamper-zcash.key   # creates the key (0600), prints only its address
//!   stamper address --network testnet --key /data/stamper-zcash.key   # prints the address
//!   stamper sign    --key /data/stamper-zcash.key < request.json       # prints {txid, hex, fee, change, logicalActions}

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use stamper_core::address::Network;
use stamper_core::build::{build, BuildRequest};
use stamper_core::key::IssuerKey;

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn network(args: &[String]) -> Result<Network, String> {
    match opt(args, "--network").as_deref() {
        Some("mainnet") => Ok(Network::Mainnet),
        Some("testnet") => Ok(Network::Testnet),
        _ => Err("--network mainnet|testnet is required".into()),
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let key_path = opt(&args, "--key").map(PathBuf::from).ok_or("--key <file> is required")?;
    match cmd {
        "keygen" => {
            let net = network(&args)?;
            let k = IssuerKey::generate();
            k.write_new(&key_path)?;
            println!("{}  {}  (new)", key_path.display(), k.address(net));
        }
        "address" => {
            let net = network(&args)?;
            println!("{}", IssuerKey::read(&key_path)?.address(net));
        }
        "sign" => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input).map_err(|e| e.to_string())?;
            let req: BuildRequest = serde_json::from_str(&input).map_err(|e| format!("bad request: {e}"))?;
            let built = build(&IssuerKey::read(&key_path)?, &req)?;
            println!("{}", serde_json::to_string(&built).map_err(|e| e.to_string())?);
        }
        _ => return Err("usage: stamper keygen|address|sign --key <file> [--network mainnet|testnet]".into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("stamper: {e}");
            ExitCode::from(1)
        }
    }
}
