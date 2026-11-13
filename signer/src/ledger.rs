//! Minimal client for the Ledger "Binance Chain" app (LedgerHQ/app-binance, v2.x).
//!
//! Protocol (from app-binance src/coin.h + src/apdu_handler.c and the official
//! bnb-chain/javascript-sdk src/ledger/ledger-app.ts):
//!   CLA 0xBC
//!   INS 0x00 GET_VERSION                      -> [test_mode, major, minor, patch, locked]
//!   INS 0x04 GET_ADDR   data=[hrp_len][hrp][path]  -> [pubkey(33)][bech32 address ascii]
//!   INS 0x03 SHOW_ADDR  data=[hrp_len][hrp][path]  -> user confirms on device, no data
//!   INS 0x02 SIGN       P1=chunk index (1-based), P2=chunk count;
//!                       chunk 1 = [path], chunks 2.. = message (<=250 bytes each)
//!                       -> DER signature over SHA-256(message)
//!   path = [5][u32 LE x5] = 44' / 714' / account' / 0 / index
//! The app only signs with the path last queried via GET_ADDR or SHOW_ADDR (both set
//! `viewed_bip32_path`). This tool always runs SHOW_ADDR right before SIGN so the owner
//! confirms the address on the device.

use ledger_apdu::APDUCommand;
use ledger_transport_hid::{TransportNativeHID, hidapi::HidApi};

const CLA: u8 = 0xBC;
const INS_GET_VERSION: u8 = 0x00;
const INS_SIGN: u8 = 0x02;
const INS_SHOW_ADDR: u8 = 0x03;
const INS_GET_ADDR: u8 = 0x04;
const CHUNK_SIZE: usize = 250;
const SW_OK: u16 = 0x9000;
const HARDENED: u32 = 0x8000_0000;

/// Highest account/index the app accepts outside expert mode.
pub const MAX_NODE: u32 = 100;

pub struct BinanceApp {
    transport: TransportNativeHID,
}

fn describe_sw(sw: u16) -> &'static str {
    match sw {
        0x6E00 | 0x6E01 | 0x6D00 => "wrong app open: open the \"Binance Chain\" app on the Ledger",
        0x5515 | 0x6982 => "Ledger is locked: unlock it and open the \"Binance Chain\" app",
        0x6986 => "rejected on the device",
        0x6985 => "conditions not satisfied (rejected, or path not allowed)",
        0x6984 => "data invalid (the app could not parse the request)",
        0x6A80 => "invalid data",
        0x6700 => "wrong length",
        _ => "unknown status word",
    }
}

pub fn path_string(account: u32, index: u32) -> String {
    format!("m/44'/714'/{account}'/0/{index}")
}

fn path_bytes(account: u32, index: u32) -> Vec<u8> {
    let nodes = [44 | HARDENED, 714 | HARDENED, account | HARDENED, 0, index];
    let mut out = Vec::with_capacity(1 + 4 * nodes.len());
    out.push(nodes.len() as u8);
    for n in nodes {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out
}

fn addr_request(account: u32, index: u32) -> Vec<u8> {
    let hrp = bbc_core::BBC_HRP.as_bytes();
    let mut data = Vec::with_capacity(1 + hrp.len() + 21);
    data.push(hrp.len() as u8);
    data.extend_from_slice(hrp);
    data.extend_from_slice(&path_bytes(account, index));
    data
}

impl BinanceApp {
    pub fn connect() -> Result<Self, String> {
        let api = HidApi::new().map_err(|e| format!("HID init failed: {e}"))?;
        let transport = TransportNativeHID::new(&api).map_err(|e| {
            format!("no Ledger found ({e}). Plug it in, unlock it, and close Ledger Live.")
        })?;
        Ok(Self { transport })
    }

    fn exchange(&self, cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Result<Vec<u8>, String> {
        let answer = self
            .transport
            .exchange(&APDUCommand { cla, ins, p1, p2, data })
            .map_err(|e| format!("USB exchange failed: {e}"))?;
        let sw = answer.retcode();
        if sw != SW_OK {
            let detail = String::from_utf8_lossy(answer.data()).trim_matches(char::from(0)).to_string();
            let detail = if detail.is_empty() { String::new() } else { format!(" [device says: {detail}]") };
            return Err(format!("Ledger returned 0x{sw:04X}: {}{detail}", describe_sw(sw)));
        }
        Ok(answer.data().to_vec())
    }

    /// Name and version of the app currently open (generic BOLOS command, works in any app).
    pub fn running_app(&self) -> Result<(String, String), String> {
        let d = self.exchange(0xB0, 0x01, 0, 0, Vec::new())?;
        // [format=1][name_len][name][version_len][version]...
        let take = |pos: usize| -> Option<(String, usize)> {
            let len = *d.get(pos)? as usize;
            let s = d.get(pos + 1..pos + 1 + len)?;
            Some((String::from_utf8_lossy(s).into_owned(), pos + 1 + len))
        };
        let (name, next) = take(1).ok_or("malformed app-info reply")?;
        let (version, _) = take(next).ok_or("malformed app-info reply")?;
        Ok((name, version))
    }

    /// (major, minor, patch) of the Binance Chain app.
    pub fn version(&self) -> Result<(u8, u8, u8), String> {
        let d = self.exchange(CLA, INS_GET_VERSION, 0, 0, Vec::new())?;
        if d.len() < 4 {
            return Err("malformed version reply".into());
        }
        if d[0] != 0 {
            return Err("the Ledger app is a TEST build (test mode flag set); refusing".into());
        }
        Ok((d[1], d[2], d[3]))
    }

    /// Returns (compressed pubkey, address string reported by the device). No confirmation needed.
    pub fn get_address(&self, account: u32, index: u32) -> Result<([u8; 33], String), String> {
        let d = self.exchange(CLA, INS_GET_ADDR, 0, 0, addr_request(account, index))?;
        if d.len() <= 33 {
            return Err("malformed address reply".into());
        }
        let mut pk = [0u8; 33];
        pk.copy_from_slice(&d[..33]);
        let addr = String::from_utf8(d[33..].to_vec()).map_err(|_| "address reply is not ASCII")?;
        Ok((pk, addr))
    }

    /// Shows the address on the device and waits for the user to confirm it.
    pub fn show_address(&self, account: u32, index: u32) -> Result<(), String> {
        self.exchange(CLA, INS_SHOW_ADDR, 0, 0, addr_request(account, index)).map(|_| ())
    }

    /// Sends the message for review on the device; returns the DER signature after approval.
    pub fn sign(&self, account: u32, index: u32, message: &[u8]) -> Result<Vec<u8>, String> {
        let mut chunks = vec![path_bytes(account, index)];
        chunks.extend(message.chunks(CHUNK_SIZE).map(<[u8]>::to_vec));
        let count = u8::try_from(chunks.len()).map_err(|_| "message too long")?;
        let mut last = Vec::new();
        for (i, chunk) in chunks.into_iter().enumerate() {
            last = self.exchange(CLA, INS_SIGN, i as u8 + 1, count, chunk)?;
        }
        if last.is_empty() {
            return Err("device returned an empty signature".into());
        }
        Ok(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_serialization_matches_js_sdk() {
        // js-sdk _serializeHDPath([44, 714, 0, 0, 0]): length byte, then int32 LE, first 3 hardened.
        assert_eq!(
            hex::encode(path_bytes(0, 0)),
            "052c000080ca020080000000800000000000000000"
        );
        // [hrp_len=3]["bnb"][path m/44'/714'/0'/0/1]
        assert_eq!(
            hex::encode(addr_request(0, 1)),
            "03626e62052c000080ca020080000000800000000001000000"
        );
    }
}
