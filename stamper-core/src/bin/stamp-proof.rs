//! Stamp proofs for private stamps (SPEC.md §9.6). No network code: the stamp transaction's raw hex
//! is passed in (from any node the user chooses); keys are read from a file, never from the command
//! line.
//!
//!   stamp-proof make  --tx <file with the raw tx hex> --params <parameter file> --viewing-key-file <file with a UFVK or UIVK>
//!                     # prints the proof and the receipt it found
//!   stamp-proof check --tx <file with the raw tx hex> --params <parameter file> --proof splg-proof:1:… [--spent-values <zat,…>]
//!                     # prints what the proof shows, what was checked and what was not (JSON), or fails
//!
//! `--spent-values`: the values of the coins the transaction's inputs spend (from any explorer or node):
//! with them the inputs' signatures are verified against the issuer key; without them the output says
//! plainly that the issuer was NOT verified (a txid does not cover signatures).
//!
//! The parameter file (params/<network>.json) names the published issuers: a transaction not spent by
//! one of them fails. Offline, this tool cannot see whether the transaction is mined or read the Solana
//! harvest; it says so in `notChecked`. The verifier's `check-proof` command checks those too.
//!   stamp-proof testwallet --network testnet --viewing-key-out <file>
//!                     # testnet only: a fresh receiving address (printed), its UFVK (written 0600) and
//!                     # its UIVK (<file>.uivk, 0600); no spending key is kept

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use stamper_core::private::proof::{check, issuers_from_params, make, receiver_address, viewing_keys, Proof};
use zcash_address::unified::{self, Encoding};
use zcash_protocol::consensus::NetworkType;

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn tx_bytes(args: &[String]) -> Result<Vec<u8>, String> {
    let path = opt(args, "--tx").ok_or("--tx <file with the raw transaction hex> is required")?;
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read --tx: {e}"))?;
    hex::decode(text.trim()).map_err(|_| "--tx must hold the raw transaction in hex".into())
}

fn params(args: &[String]) -> Result<(NetworkType, Vec<[u8; 20]>), String> {
    let path = opt(args, "--params").ok_or("--params <parameter file> is required (it names the published issuers)")?;
    issuers_from_params(&fs::read_to_string(path).map_err(|e| format!("cannot read --params: {e}"))?)
}

fn network(args: &[String]) -> Result<NetworkType, String> {
    match opt(args, "--network").as_deref() {
        None | Some("mainnet") => Ok(NetworkType::Main),
        Some("testnet") => Ok(NetworkType::Test),
        _ => Err("--network mainnet|testnet".into()),
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or("") {
        "make" => {
            let tx = tx_bytes(&args)?;
            let path = opt(&args, "--viewing-key-file").ok_or("--viewing-key-file <file> is required (a key is never taken from the command line)")?;
            let (net, issuers) = params(&args)?;
            let (key_net, keys) = viewing_keys(&fs::read_to_string(path).map_err(|_| "cannot read the viewing key file")?)?;
            if key_net != net {
                return Err("the viewing key is for another network than the parameter file".into());
            }
            let p = make(&tx, &keys)?;
            let shown = check(&tx, &p, net, &issuers, None)?;
            println!("{}", p.encode());
            eprintln!("delivered to {}\n{}", shown.address, shown.receipt.text()?);
        }
        "check" => {
            let tx = tx_bytes(&args)?;
            let p = Proof::decode(&opt(&args, "--proof").ok_or("--proof <splg-proof:1:…> is required")?)?;
            let (net, issuers) = params(&args)?;
            let values = opt(&args, "--spent-values").map(|s| s.split(',').map(|v| v.trim().parse::<u64>().map_err(|_| "--spent-values takes zatoshi amounts, comma-separated".to_string())).collect::<Result<Vec<_>, _>>()).transpose()?;
            let shown = check(&tx, &p, net, &issuers, values.as_deref())?;
            if !shown.issuer_verified {
                eprintln!("NOTE: the issuer was NOT verified (no --spent-values): see notChecked");
            }
            println!("{}", serde_json::to_string_pretty(&shown).map_err(|e| e.to_string())?);
        }
        "testwallet" => {
            if network(&args)? != NetworkType::Test {
                return Err("testwallet is for testnet only".into());
            }
            let out = PathBuf::from(opt(&args, "--viewing-key-out").ok_or("--viewing-key-out <file> is required")?);
            if out.exists() {
                return Err(format!("{} already exists", out.display()));
            }
            let sk = loop {
                let mut b = [0u8; 32];
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
                if let Some(sk) = Option::<orchard::keys::SpendingKey>::from(orchard::keys::SpendingKey::from_bytes(b)) {
                    break sk;
                }
            };
            let fvk = orchard::keys::FullViewingKey::from(&sk as &orchard::keys::SpendingKey);
            let addr = fvk.address_at(0u32, orchard::keys::Scope::External).to_raw_address_bytes();
            let ufvk = unified::Ufvk::try_from_items(vec![unified::Fvk::Orchard(fvk.to_bytes())]).map_err(|e| e.to_string())?.encode(&NetworkType::Test);
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let uivk = unified::Uivk::try_from_items(vec![unified::Ivk::Orchard(fvk.to_ivk(orchard::keys::Scope::External).to_bytes())]).map_err(|e| e.to_string())?.encode(&NetworkType::Test);
            use std::io::Write;
            opts.open(&out).and_then(|mut f| f.write_all(format!("{ufvk}\n").as_bytes())).map_err(|e| e.to_string())?;
            let uivk_path = PathBuf::from(format!("{}.uivk", out.display()));
            opts.open(&uivk_path).and_then(|mut f| f.write_all(format!("{uivk}\n").as_bytes())).map_err(|e| e.to_string())?;
            println!("{}", receiver_address(&addr, NetworkType::Test));
        }
        _ => return Err("usage: stamp-proof make|check|testwallet …".into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("stamp-proof: {e}");
            ExitCode::from(1)
        }
    }
}
