//! The receipt a payout stamp's note carries in its memo (SPEC.md §10.3): UTF-8 text (ZIP 302: the first
//! byte is below 0xF5), nine lines in a fixed order, readable in any wallet and parsed back exactly.
//!
//! ```text
//! SPLG/3 shielded exit
//! from <sell|harvest|send>[ $<TICKER> <mint>]
//! sent <ZEC, 8 decimals> ZEC          what the Solana transaction sent to the bridge
//! bridged <ZEC, 8 decimals> ZEC       what the bridge delivered to the order's address
//! fee <ZEC, 8 decimals> ZEC           this exit's share of the Zcash network fee
//! received <ZEC, 8 decimals> ZEC      this note: bridged − fee
//! solana <Solana signature>
//! at <block time, ISO 8601 UTC>
//! sapling.cash/zec/exit/<Solana signature>
//! ```

use serde::Serialize;

use crate::private::memo::u64_string;

pub const HEADER: &str = "SPLG/3 shielded exit";
pub const MEMO_LEN: usize = 512;
const LINK: &str = "sapling.cash/zec/exit/";

/// A version 3 receipt. Amounts are zatoshi; `received` is always `bridged − fee`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayoutReceipt {
    /// `sell`, `harvest` or `send`
    pub kind: String,
    /// the coin sold or harvested (absent for `send`)
    pub ticker: Option<String>,
    pub mint: Option<String>,
    #[serde(with = "u64_string")]
    pub sent: u64,
    #[serde(with = "u64_string")]
    pub bridged: u64,
    #[serde(with = "u64_string")]
    pub fee: u64,
    #[serde(with = "u64_string")]
    pub received: u64,
    /// the exit's Solana signature, base58
    pub signature: String,
    /// its block time, unix seconds
    pub block_time: i64,
}

fn decimal(v: u64) -> String {
    format!("{}.{:08}", v / 100_000_000, v % 100_000_000)
}

fn parse_decimal(s: &str) -> Option<u64> {
    let (i, f) = s.split_once('.')?;
    if f.len() != 8 || i.is_empty() || !i.bytes().chain(f.bytes()).all(|b| b.is_ascii_digit()) || (i.len() > 1 && i.starts_with('0')) {
        return None;
    }
    i.parse::<u64>().ok()?.checked_mul(100_000_000)?.checked_add(f.parse::<u64>().ok()?)
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (H. Hinnant's civil_from_days).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn iso(t: i64) -> String {
    let (y, m, d) = civil(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3_600, s % 3_600 / 60, s % 60)
}

fn parse_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let t = days * 86_400 + hh * 3_600 + mm * 60 + ss;
    (iso(t) == s).then_some(t)
}

fn is_ticker(t: &str) -> bool {
    (1..=10).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn is_base58(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && bs58::decode(s).into_vec().is_ok()
}

impl PayoutReceipt {
    /// The receipt's text: exactly what the note's memo holds before its zero padding.
    pub fn text(&self) -> Result<String, String> {
        match (self.kind.as_str(), &self.ticker, &self.mint) {
            ("sell" | "harvest", Some(t), Some(m)) if is_ticker(t) && is_base58(m, 32, 44) => {}
            ("send", None, None) => {}
            _ => return Err("the receipt's source must be sell or harvest with a ticker and mint, or send with neither".into()),
        }
        if !is_base58(&self.signature, 64, 90) {
            return Err("the receipt's signature is not base58".into());
        }
        if self.block_time < 0 {
            return Err("the receipt's time is before 1970".into());
        }
        if self.bridged.checked_sub(self.fee) != Some(self.received) {
            return Err("received is not bridged − fee".into());
        }
        let from = match (&self.ticker, &self.mint) {
            (Some(t), Some(m)) => format!("{} ${t} {m}", self.kind),
            _ => self.kind.clone(),
        };
        let t = format!(
            "{HEADER}\nfrom {from}\nsent {} ZEC\nbridged {} ZEC\nfee {} ZEC\nreceived {} ZEC\nsolana {}\nat {}\n{LINK}{}",
            decimal(self.sent),
            decimal(self.bridged),
            decimal(self.fee),
            decimal(self.received),
            self.signature,
            iso(self.block_time),
            self.signature
        );
        if t.len() > MEMO_LEN {
            return Err("the receipt does not fit in a memo".into());
        }
        Ok(t)
    }

    /// The 512-byte memo field: the text, zero-padded.
    pub fn memo(&self) -> Result<[u8; MEMO_LEN], String> {
        let t = self.text()?;
        let mut m = [0u8; MEMO_LEN];
        m[..t.len()].copy_from_slice(t.as_bytes());
        Ok(m)
    }

    /// Parses a memo field. Anything that is not exactly what [`PayoutReceipt::text`] writes is refused.
    pub fn parse(memo: &[u8]) -> Result<PayoutReceipt, String> {
        let bad = || "the memo is not a version 3 receipt (SPLG/3)".to_string();
        let end = memo.iter().position(|b| *b == 0).unwrap_or(memo.len());
        if memo[end..].iter().any(|b| *b != 0) {
            return Err(bad());
        }
        let text = std::str::from_utf8(&memo[..end]).map_err(|_| bad())?;
        let lines: Vec<&str> = text.split('\n').collect();
        if lines.len() != 9 || lines[0] != HEADER {
            return Err(bad());
        }
        let field = |i: usize, key: &str| lines[i].strip_prefix(key).ok_or_else(bad);
        let zec = |i: usize, key: &str| -> Result<u64, String> { parse_decimal(field(i, key)?.strip_suffix(" ZEC").ok_or_else(bad)?).ok_or_else(bad) };
        let from: Vec<&str> = field(1, "from ")?.split(' ').collect();
        let (kind, ticker, mint) = match from.as_slice() {
            [k] => (k.to_string(), None, None),
            [k, t, m] => (k.to_string(), Some(t.strip_prefix('$').ok_or_else(bad)?.to_string()), Some(m.to_string())),
            _ => return Err(bad()),
        };
        let r = PayoutReceipt {
            kind,
            ticker,
            mint,
            sent: zec(2, "sent ")?,
            bridged: zec(3, "bridged ")?,
            fee: zec(4, "fee ")?,
            received: zec(5, "received ")?,
            signature: field(6, "solana ")?.to_string(),
            block_time: parse_iso(field(7, "at ")?).ok_or_else(bad)?,
        };
        if r.text().map_err(|_| bad())? != text {
            return Err(bad());
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(kind: &str) -> PayoutReceipt {
        let coin = kind != "send";
        PayoutReceipt {
            kind: kind.into(),
            ticker: coin.then(|| "LONGESTTKR".into()),
            mint: coin.then(|| bs58::encode([200u8; 32]).into_string()),
            sent: 1_234_567_890,
            bridged: 1_234_500_000,
            fee: 15_000,
            received: 1_234_485_000,
            signature: bs58::encode([255u8; 64]).into_string(),
            block_time: 1_790_611_200,
        }
    }

    #[test]
    fn writes_and_parses_back_every_source() {
        for kind in ["sell", "harvest", "send"] {
            let rec = r(kind);
            assert_eq!(PayoutReceipt::parse(&rec.memo().unwrap()).unwrap(), rec);
        }
        let t = r("harvest").text().unwrap();
        assert!(t.starts_with("SPLG/3 shielded exit\nfrom harvest $LONGESTTKR "));
        assert!(t.contains("\nat 2026-09-28T16:00:00Z\n"));
        assert!(t.ends_with(&format!("\nsapling.cash/zec/exit/{}", r("send").signature)));
    }

    #[test]
    fn refuses_what_it_would_not_write() {
        assert!(PayoutReceipt { ticker: None, ..r("sell") }.text().is_err());
        assert!(PayoutReceipt { ticker: Some("lower".into()), ..r("sell") }.text().is_err());
        assert!(PayoutReceipt { received: 1, ..r("send") }.text().is_err());
        assert!(PayoutReceipt { fee: 1_234_500_001, received: 0, ..r("send") }.text().is_err());
        let mut memo = r("sell").memo().unwrap();
        memo[25] ^= 1;
        assert!(PayoutReceipt::parse(&memo).is_err());
        let mut memo = r("sell").memo().unwrap();
        memo[511] = 1;
        assert!(PayoutReceipt::parse(&memo).is_err());
        assert!(PayoutReceipt::parse(b"SPLG/2 private stamp").is_err());
    }

    #[test]
    fn dates() {
        for t in [0i64, 951_782_400, 1_790_611_200, 4_102_444_799] {
            assert_eq!(parse_iso(&iso(t)), Some(t));
        }
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(parse_iso("2026-02-30T00:00:00Z"), None);
    }
}
