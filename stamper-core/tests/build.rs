//! Fees (ZIP 317), change, the refusals, and the key file.

use stamper_core::address::{hash160, p2pkh_address, p2pkh_script, Network};
use stamper_core::build::{build, zip317_fee, BuildRequest, Output, Utxo};
use stamper_core::key::IssuerKey;

fn key() -> IssuerKey {
    IssuerKey::from_bytes(&[3; 32]).unwrap()
}
fn record() -> Output {
    Output { value: 0, script: format!("6a34{}", "02".repeat(52)) }
}
fn postage_p2pkh() -> Output {
    Output { value: 546, script: hex::encode(p2pkh_script(&hash160(b"h"))) }
}
fn req(value: u64, outputs: Vec<Output>, fee: u64) -> BuildRequest {
    BuildRequest { consensus_branch_id: 0x37A5_165B, expiry_height: 100, marginal_fee: fee, inputs: vec![Utxo { txid: "bb".repeat(32), vout: 2, value }], outputs }
}

#[test]
fn a_stamp_is_4_logical_actions() {
    // 1 input (150), outputs: OP_RETURN 8+1+54 = 63, P2PKH 34, change 34 → ⌈131/34⌉ = 4
    assert_eq!(zip317_fee(1, &[54, 25, 25], 5_000), (20_000, 4));
    assert_eq!(zip317_fee(1, &[54, 25, 25], 1_000), (4_000, 4));
    // a P2SH postage (23-byte script) is the same
    assert_eq!(zip317_fee(1, &[54, 23, 25], 5_000), (20_000, 4));
    // the grace minimum of 2
    assert_eq!(zip317_fee(1, &[25], 5_000), (10_000, 2));
    let b = build(&key(), &req(1_000_000, vec![record(), postage_p2pkh()], 5_000)).unwrap();
    assert_eq!((b.fee, b.logical_actions, b.change), (20_000, 4, 1_000_000 - 546 - 20_000));
}

#[test]
fn a_split_into_ten_coins() {
    let outs: Vec<Output> = (0..10).map(|_| Output { value: 100_000, script: hex::encode(p2pkh_script(&key().pubkey_hash())) }).collect();
    let b = build(&key(), &req(2_000_000, outs, 5_000)).unwrap();
    assert_eq!(b.logical_actions, 11); // 11 outputs of 34 bytes
    assert_eq!(b.fee, 55_000);
}

#[test]
fn dust_change_goes_to_the_fee_instead() {
    // inputs cover outputs + the fee without change (3 actions → 15,000) + 40 zat: no change output
    let v = 546 + 15_000 + 40;
    let b = build(&key(), &req(v, vec![record(), postage_p2pkh()], 5_000)).unwrap();
    assert_eq!(b.change, 0);
    assert_eq!(b.fee, 15_040);
    assert_eq!(b.logical_actions, 3);
}

#[test]
fn refuses_what_it_should_not_build() {
    let k = key();
    let err = |r: BuildRequest| build(&k, &r).unwrap_err();
    assert!(err(req(1_000, vec![record(), postage_p2pkh()], 5_000)).contains("do not cover"));
    assert!(err(req(1_000_000, vec![record(), record(), postage_p2pkh()], 5_000)).contains("at most one OP_RETURN"));
    assert!(err(req(1_000_000, vec![Output { value: 1, script: record().script }], 5_000)).contains("0 zat"));
    assert!(err(req(1_000_000, vec![Output { value: 0, script: format!("6a{}", "00".repeat(83)) }], 5_000)).contains("83"));
    assert!(err(req(1_000_000, vec![Output { value: 53, script: postage_p2pkh().script }], 5_000)).contains("dust"));
    assert!(err(req(1_000_000, vec![Output { value: 1_000, script: "51".into() }], 5_000)).contains("only P2PKH"));
    assert!(err(req(1_000_000, vec![postage_p2pkh()], 0)).contains("positive"));
    let mut none = req(1_000_000, vec![postage_p2pkh()], 5_000);
    none.inputs.clear();
    assert!(err(none).contains("no inputs"));
}

#[test]
fn the_key_file_is_0600_never_overwritten_and_only_the_address_is_shown() {
    let dir = std::env::temp_dir().join(format!("stamper-key-{}", std::process::id()));
    let path = dir.join("issuer.key");
    let k = IssuerKey::generate();
    k.write_new(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert!(IssuerKey::generate().write_new(&path).unwrap_err().contains("refusing to overwrite"));
    let back = IssuerKey::read(&path).unwrap();
    assert_eq!(back.address(Network::Testnet), k.address(Network::Testnet));
    assert!(k.address(Network::Testnet).starts_with("tm"));
    assert!(k.address(Network::Mainnet).starts_with("t1"));
    assert_eq!(p2pkh_address(Network::Mainnet, &k.pubkey_hash()), k.address(Network::Mainnet));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_cli_prints_the_address_but_never_the_key() {
    let dir = std::env::temp_dir().join(format!("stamper-cli-{}", std::process::id()));
    let path = dir.join("k.key");
    let bin = env!("CARGO_BIN_EXE_stamper");
    let out = std::process::Command::new(bin).args(["keygen", "--network", "testnet", "--key"]).arg(&path).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let secret = std::fs::read_to_string(&path).unwrap();
    assert!(!stdout.contains(secret.trim()), "the key is never printed");
    assert!(stdout.contains(" tm"), "the testnet address is printed");
    // sign from stdin
    let mut child = std::process::Command::new(bin).args(["sign", "--key"]).arg(&path).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
    use std::io::Write;
    let body = serde_json::json!({ "consensusBranchId": 0x37A5165Bu32, "expiryHeight": 10, "marginalFee": 5000, "inputs": [{ "txid": "cc".repeat(32), "vout": 0, "value": 300000 }], "outputs": [{ "value": 546, "script": postage_p2pkh().script }] });
    child.stdin.take().unwrap().write_all(body.to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["txid"].as_str().unwrap().len(), 64);
    assert!(!String::from_utf8_lossy(&out.stdout).contains(secret.trim()));
    // a second keygen refuses
    let again = std::process::Command::new(bin).args(["keygen", "--network", "testnet", "--key"]).arg(&path).output().unwrap();
    assert!(!again.status.success());
    std::fs::remove_dir_all(&dir).unwrap();
}
