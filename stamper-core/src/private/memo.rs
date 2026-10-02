//! The receipt a private stamp carries in its shielded memo (SPEC.md §9.3): UTF-8 text (ZIP 302: the
//! first byte is below 0xF5), nine lines in a fixed order, readable in any wallet and parseable back
//! exactly.
//!
//! ```text
//! SPLG/2 private stamp
//! coin $<TICKER> <mint>
//! burned <coin amount, 6 decimals>
//! harvested <ZEC, 8 decimals> ZEC
//! fee <ZEC, 8 decimals> ZEC
//! received <ZEC, 8 decimals> ZEC
//! harvest <Solana signature>
//! at <block time, ISO 8601 UTC>
//! sapling.cash/stamp/<Solana signature>
//! ```

use serde::{Deserialize, Serialize};

pub const HEADER: &str = "SPLG/2 private stamp";
pub const MEMO_LEN: usize = 512;
const LINK: &str = "sapling.cash/stamp/";
const COIN_DECIMALS: u32 = 6;
const ZEC_DECIMALS: u32 = 8;

/// What a receipt says. Amounts are base units; the fee must not exceed the harvested amount.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub ticker: String,
    pub mint: String,
    #[serde(with = "u64_string")]
    pub burned: u64,
    #[serde(with = "u64_string")]
    pub harvested: u64,
    #[serde(with = "u64_string")]
    pub fee: u64,
    /// the harvest's Solana signature, base58
    pub signature: String,
    /// the harvest's block time, unix seconds
    pub block_time: i64,
}

pub(crate) mod u64_string {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
            return Err(serde::de::Error::custom("an amount must be a decimal string of base units"));
        }
        s.parse().map_err(serde::de::Error::custom)
    }
}

fn decimal(v: u64, places: u32) -> String {
    let unit = 10u64.pow(places);
    format!("{}.{:0width$}", v / unit, v % unit, width = places as usize)
}

fn parse_decimal(s: &str, places: u32) -> Option<u64> {
    let (int, frac) = s.split_once('.')?;
    if int.is_empty() || frac.len() != places as usize || !int.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) || (int.len() > 1 && int.starts_with('0')) {
        return None;
    }
    int.parse::<u64>().ok()?.checked_mul(10u64.pow(places))?.checked_add(frac.parse().ok()?)
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (H. Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn iso(t: i64) -> String {
    let (y, m, d) = civil(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

fn valid_ticker(t: &str) -> bool {
    // 1 to 10 ASCII letters or digits: nothing a wallet could render differently from what it is
    // (no right-to-left overrides or other format characters, no look-alike scripts)
    !t.is_empty() && t.len() <= 10 && t.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn valid_b58(s: &str, min: usize, max: usize) -> bool {
    s.len() >= min && s.len() <= max && bs58::decode(s).into_vec().is_ok()
}

impl Receipt {
    pub fn check(&self) -> Result<(), String> {
        if !valid_ticker(&self.ticker) {
            return Err("the ticker must be 1 to 10 ASCII letters or digits".into());
        }
        if !valid_b58(&self.mint, 32, 44) || bs58::decode(&self.mint).into_vec().map(|v| v.len()) != Ok(32) {
            return Err("the mint must be a base58 public key".into());
        }
        if !valid_b58(&self.signature, 64, 88) || bs58::decode(&self.signature).into_vec().map(|v| v.len()) != Ok(64) {
            return Err("the signature must be a base58 Solana signature".into());
        }
        if self.fee > self.harvested {
            return Err("the fee exceeds the harvested amount".into());
        }
        if !(0..=253_402_300_799).contains(&self.block_time) {
            return Err("the block time is out of range".into());
        }
        Ok(())
    }

    /// The receipt as text (at most 439 bytes).
    pub fn text(&self) -> Result<String, String> {
        self.check()?;
        let t = format!(
            "{HEADER}\ncoin ${} {}\nburned {}\nharvested {} ZEC\nfee {} ZEC\nreceived {} ZEC\nharvest {}\nat {}\n{LINK}{}",
            self.ticker,
            self.mint,
            decimal(self.burned, COIN_DECIMALS),
            decimal(self.harvested, ZEC_DECIMALS),
            decimal(self.fee, ZEC_DECIMALS),
            decimal(self.harvested - self.fee, ZEC_DECIMALS),
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

    /// Parses a memo field back. Anything that is not exactly a version 2 receipt is refused.
    pub fn parse(memo: &[u8]) -> Result<Receipt, String> {
        let end = memo.iter().position(|b| *b == 0).unwrap_or(memo.len());
        if memo[end..].iter().any(|b| *b != 0) {
            return Err("bytes after the text are not zero".into());
        }
        let text = std::str::from_utf8(&memo[..end]).map_err(|_| "the memo is not UTF-8".to_string())?;
        let bad = || "not a version 2 receipt".to_string();
        let lines: Vec<&str> = text.split('\n').collect();
        if lines.len() != 9 || lines[0] != HEADER {
            return Err(bad());
        }
        let field = |i: usize, key: &str| lines[i].strip_prefix(key).ok_or_else(bad);
        let (ticker, mint) = field(1, "coin $")?.split_once(' ').ok_or_else(bad)?;
        let burned = parse_decimal(field(2, "burned ")?, COIN_DECIMALS).ok_or_else(bad)?;
        let zec = |i: usize, key: &str| -> Result<u64, String> { parse_decimal(field(i, key)?.strip_suffix(" ZEC").ok_or_else(bad)?, ZEC_DECIMALS).ok_or_else(bad) };
        let harvested = zec(3, "harvested ")?;
        let fee = zec(4, "fee ")?;
        let received = zec(5, "received ")?;
        let signature = field(6, "harvest ")?;
        let at = field(7, "at ")?;
        let link = field(8, LINK)?;
        let r = Receipt { ticker: ticker.into(), mint: mint.into(), burned, harvested, fee, signature: signature.into(), block_time: 0 };
        // the time and every derived line must be exactly what `text` writes
        let block_time = parse_iso(at).ok_or_else(bad)?;
        let r = Receipt { block_time, ..r };
        r.check()?;
        if received != harvested - fee || link != signature || r.text()? != text {
            return Err(bad());
        }
        Ok(r)
    }
}

fn parse_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    // days from civil (the inverse of `civil`)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let t = (era * 146_097 + doe - 719_468) * 86_400 + h * 3600 + mi * 60 + se;
    (iso(t) == s).then_some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Receipt {
        Receipt {
            ticker: "ROOT".into(),
            mint: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".into(),
            burned: 1_250_000_000_000,
            harvested: 1_234_567,
            fee: 40_000,
            signature: bs58::encode([9u8; 64]).into_string(),
            block_time: 1_790_424_000,
        }
    }

    #[test]
    fn text_and_parse_round_trip() {
        let r = sample();
        let t = r.text().unwrap();
        assert!(t.starts_with("SPLG/2 private stamp\ncoin $ROOT 7xKX"));
        assert!(t.contains("\nburned 1250000.000000\nharvested 0.01234567 ZEC\nfee 0.00040000 ZEC\nreceived 0.01194567 ZEC\n"));
        assert!(t.contains("\nat 2026-09-26T12:00:00Z\n"));
        assert_eq!(Receipt::parse(&r.memo().unwrap()).unwrap(), r);
        assert!(r.memo().unwrap()[0] < 0xf5, "ZIP 302 text memo");
    }

    #[test]
    fn worst_case_fits_in_439_bytes() {
        let r = Receipt {
            ticker: "ABCDEFGHIJ".into(),
            mint: bs58::encode([0xffu8; 32]).into_string(),
            burned: u64::MAX,
            harvested: u64::MAX,
            // the longest fee and received lines together: both 20 characters
            fee: 9_999_999_999_999_999_999,
            signature: bs58::encode([0xffu8; 64]).into_string(),
            block_time: 253_402_300_799,
        };
        assert_eq!(r.mint.len(), 44);
        assert_eq!(r.signature.len(), 88);
        let t = r.text().unwrap();
        assert_eq!(t.len(), 439);
        assert_eq!(Receipt::parse(&r.memo().unwrap()).unwrap(), r);
    }

    #[test]
    fn anything_else_is_refused() {
        let good = sample().text().unwrap();
        let cases = [
            good.replace("SPLG/2", "SPLG/3"),
            good.replace("0.01194567", "0.01194568"),
            good.replace("12:00:00Z", "12:00:60Z"),
            good.replace("burned 1250000.000000", "burned 1250000.00000"),
            good.replace("burned 1250000", "burned 01250000"),
            good.clone() + "\n",
            good.replace("\n", "\r\n"),
        ];
        for c in cases {
            let mut m = [0u8; MEMO_LEN];
            m[..c.len()].copy_from_slice(c.as_bytes());
            assert!(Receipt::parse(&m).is_err(), "{c}");
        }
        let mut m = sample().memo().unwrap();
        m[511] = 1;
        assert!(Receipt::parse(&m).is_err());
    }

    #[test]
    fn iso_times() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00Z");
        for t in [0, 951_782_400, 1_790_424_000, 4_102_444_799, 253_402_300_799] {
            assert_eq!(parse_iso(&iso(t)), Some(t));
        }
        assert_eq!(parse_iso("2026-02-30T00:00:00Z"), None);
    }

    #[test]
    fn a_ticker_is_ascii_letters_and_digits_only() {
        for bad in ["AB\u{202e}CD", "é", "A B", "A\u{200b}B", "", "ABCDEFGHIJK", "A-B"] {
            assert!(Receipt { ticker: bad.into(), ..sample() }.text().is_err(), "{bad:?}");
        }
        assert!(Receipt { ticker: "Pepe2".into(), ..sample() }.text().is_ok());
    }
}
