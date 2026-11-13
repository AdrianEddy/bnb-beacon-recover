//! bbc-core: network-free logic shared by `bbc-sign` (offline) and `bbc-submit` (online).
//!
//! It builds the exact message a BNB Beacon Chain key signs to authorise a token recovery,
//! derives Beacon Chain addresses from public keys, and verifies signatures. Everything that
//! ends up inside the signed message is constructed in this file, so reviewing this file tells
//! you exactly what gets signed.

pub use alloy_primitives::Address;
use alloy_primitives::U256;
use bech32::{Bech32, Hrp};
use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Beacon Chain mainnet chain id. Equals `SOURCE_CHAIN_ID` of the BSC TokenRecoverPortal
/// contract (0x...3000) on mainnet.
pub const CHAIN_ID: &str = "Binance-Chain-Tigris";
/// Beacon Chain bech32 prefix.
pub const BBC_HRP: &str = "bnb";
/// Beacon Chain token decimals (all BEP2/BEP8 tokens and BNB).
pub const BEACON_DECIMALS: u32 = 8;
/// Symbol of native BNB on the Beacon Chain.
pub const NATIVE_SYMBOL: &str = "BNB";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid BSC address {0} (copy it exactly, in EIP-55 mixed-case form, from your wallet or BscScan)")]
    BadAddress(String),
    #[error("the recipient must not be the zero address")]
    ZeroRecipient,
    #[error("invalid Beacon Chain address: {0}")]
    BadBbcAddress(String),
    #[error("invalid token symbol {0:?}: 1..=31 printable ASCII characters, exactly as the official API lists it")]
    BadSymbol(String),
    #[error("invalid amount {0:?}: a positive decimal number with at most 8 decimals, exactly as the official API lists it")]
    BadAmount(String),
    #[error("invalid public key: {0}")]
    BadPublicKey(String),
    #[error("invalid signature: {0}")]
    BadSignature(String),
    #[error("check failed: {0}")]
    Mismatch(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Parses an EIP-55 checksummed BSC/EVM address. All-lowercase input is rejected because it
/// carries no checksum, so a typo cannot slip through.
pub fn parse_checksummed(addr: &str) -> Result<Address> {
    Address::parse_checksummed(addr.trim(), None).map_err(|e| Error::BadAddress(format!("{addr}: {e}")))
}

/// A recipient: checksummed and not the zero address.
pub fn parse_recipient(addr: &str) -> Result<Address> {
    let a = parse_checksummed(addr)?;
    if a.is_zero() {
        return Err(Error::ZeroRecipient);
    }
    Ok(a)
}

/// The 20-byte payload of a Beacon Chain bech32 address (= RIPEMD160(SHA256(pubkey)), the
/// `ownerAddr` the contract puts in the Merkle leaf).
pub fn bbc_address_payload(address: &str) -> Result<[u8; 20]> {
    let (hrp, data) = bech32::decode(address).map_err(|e| Error::BadBbcAddress(format!("{address}: {e}")))?;
    if hrp.to_lowercase() != BBC_HRP {
        return Err(Error::BadBbcAddress(format!("{address}: expected prefix {BBC_HRP}1, got {hrp}")));
    }
    data.try_into()
        .map_err(|d: Vec<u8>| Error::BadBbcAddress(format!("{address}: expected a 20-byte payload, got {}", d.len())))
}

/// Validates a `bnb1...` address and returns it in canonical (lowercase) form.
pub fn parse_bbc_address(address: &str) -> Result<String> {
    let payload = bbc_address_payload(address.trim())?;
    encode_bbc_address(&payload)
}

fn encode_bbc_address(payload: &[u8; 20]) -> Result<String> {
    let hrp = Hrp::parse(BBC_HRP).map_err(|e| Error::BadBbcAddress(e.to_string()))?;
    bech32::encode::<Bech32>(hrp, payload).map_err(|e| Error::BadBbcAddress(e.to_string()))
}

/// Beacon Chain address of a compressed secp256k1 public key: bech32("bnb", RIPEMD160(SHA256(pubkey))).
pub fn bbc_address(pubkey: &[u8]) -> Result<String> {
    if pubkey.len() != 33 {
        return Err(Error::BadPublicKey(format!("expected 33 bytes (compressed), got {}", pubkey.len())));
    }
    VerifyingKey::from_sec1_bytes(pubkey).map_err(|e| Error::BadPublicKey(e.to_string()))?;
    let h160: [u8; 20] = Ripemd160::digest(Sha256::digest(pubkey)).into();
    encode_bbc_address(&h160)
}

/// Checks a token symbol: 1..=31 printable ASCII characters (it is encoded as a bytes32 string).
pub fn validate_symbol(symbol: &str) -> Result<()> {
    if symbol.is_empty() || symbol.len() > 31 || !symbol.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::BadSymbol(symbol.to_string()));
    }
    Ok(())
}

/// `bytes32` encoding of a token symbol, same as ethers `encodeBytes32String`
/// (bytes right-padded with zeros, at most 31 bytes).
pub fn symbol_bytes32(symbol: &str) -> Result<[u8; 32]> {
    validate_symbol(symbol)?;
    let mut out = [0u8; 32];
    out[..symbol.len()].copy_from_slice(symbol.as_bytes());
    Ok(out)
}

/// `uint256` big-endian encoding of an amount.
pub fn amount_bytes32(amount: u64) -> [u8; 32] {
    U256::from(amount).to_be_bytes::<32>()
}

/// Parses a decimal amount ("12.5", "0.00001") into Beacon Chain base units (8 decimals).
/// Exact: no floating point, no rounding, more than 8 decimals is an error.
pub fn parse_amount(text: &str) -> Result<u64> {
    let bad = || Error::BadAmount(text.to_string());
    let t = text.trim();
    let (int, frac) = t.split_once('.').unwrap_or((t, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if int.is_empty() || !digits(int) || !digits(frac) || frac.len() > BEACON_DECIMALS as usize || t.ends_with('.') {
        return Err(bad());
    }
    let scale = 10u64.pow(BEACON_DECIMALS);
    let int: u64 = int.parse().map_err(|_| bad())?;
    let frac: u64 = format!("{frac:0<width$}", width = BEACON_DECIMALS as usize).parse().map_err(|_| bad())?;
    let units = int.checked_mul(scale).and_then(|v| v.checked_add(frac)).ok_or_else(bad)?;
    if units == 0 {
        return Err(bad());
    }
    Ok(units)
}

/// Human-readable Beacon Chain amount (8 decimals).
pub fn format_amount(base_units: u64) -> String {
    let scale = 10u64.pow(BEACON_DECIMALS);
    format!("{}.{:0width$}", base_units / scale, base_units % scale, width = BEACON_DECIMALS as usize)
}

/// Amino-style sign doc. Field order is alphabetical on purpose and must stay so: the official
/// tool sorts keys, the Ledger app rejects unsorted JSON, and the contract rebuilds this exact
/// byte layout (`_tmSignatureHash` in TokenRecoverPortal.sol).
#[derive(Serialize)]
struct SignDoc<'a> {
    account_number: &'a str,
    chain_id: &'a str,
    data: Option<()>,
    memo: &'a str,
    msgs: [RecoverMsg; 1],
    sequence: &'a str,
    source: &'a str,
}

#[derive(Serialize)]
struct RecoverMsg {
    amount: String,
    recipient: String,
    token_symbol: String,
}

/// The exact bytes the Beacon Chain key signs (the official tool's `getSignBytes`).
pub fn sign_bytes(chain_id: &str, symbol: &str, amount: u64, recipient: &Address) -> Result<Vec<u8>> {
    let doc = SignDoc {
        account_number: "0",
        chain_id,
        data: None,
        memo: "",
        msgs: [RecoverMsg {
            amount: hex::encode(amount_bytes32(amount)),
            recipient: format!("0x{}", hex::encode(recipient.as_slice())),
            token_symbol: hex::encode(symbol_bytes32(symbol)?),
        }],
        sequence: "0",
        source: "0",
    };
    Ok(serde_json::to_vec(&doc)?)
}

/// What one recovery claims: the full snapshot balance of one token held by one Beacon Chain
/// address, sent to one BSC address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRequest {
    /// Canonical `bnb1...` address that held the balance.
    pub bbc_address: String,
    /// Token symbol exactly as the official API lists it ("BNB", "CAKE-435", ...).
    pub token_symbol: String,
    /// Full snapshot balance in base units (8 decimals). The Merkle leaf commits to it.
    pub amount_base_units: u64,
    /// BSC address that receives the funds. It must also send the `recover()` transaction.
    pub recipient: Address,
}

impl RecoveryRequest {
    /// Validates and assembles a request from user input (amount as a decimal string).
    pub fn parse(bbc_address: &str, token_symbol: &str, amount: &str, recipient: &str) -> Result<Self> {
        validate_symbol(token_symbol)?;
        Ok(Self {
            bbc_address: parse_bbc_address(bbc_address)?,
            token_symbol: token_symbol.to_string(),
            amount_base_units: parse_amount(amount)?,
            recipient: parse_recipient(recipient)?,
        })
    }

    /// The message the Beacon Chain key must sign.
    pub fn message(&self) -> Result<String> {
        let bytes = sign_bytes(CHAIN_ID, &self.token_symbol, self.amount_base_units, &self.recipient)?;
        String::from_utf8(bytes).map_err(|e| Error::Mismatch(format!("sign bytes are not UTF-8: {e}")))
    }

    /// e.g. "12.50000000 BNB".
    pub fn amount_display(&self) -> String {
        format!("{} {}", format_amount(self.amount_base_units), self.token_symbol)
    }
}

/// Verifies a 64-byte r||s signature over SHA-256(message). High-S signatures are rejected:
/// the BSC precompile that checks them (Tendermint secp256k1) rejects them too.
pub fn verify_signature(message: &[u8], pubkey: &[u8], sig64: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey).map_err(|e| Error::BadPublicKey(e.to_string()))?;
    let sig = Signature::from_slice(sig64).map_err(|e| Error::BadSignature(e.to_string()))?;
    if sig.normalize_s().is_some() {
        return Err(Error::BadSignature("signature is not low-S normalized".into()));
    }
    vk.verify(message, &sig).map_err(|e| Error::BadSignature(e.to_string()))
}

/// Converts a DER signature (as returned by the Ledger app) to low-S 64-byte r||s.
pub fn der_to_compact_low_s(der: &[u8]) -> Result<[u8; 64]> {
    let sig = Signature::from_der(der).map_err(|e| Error::BadSignature(e.to_string()))?;
    Ok(compact_low_s(&sig))
}

/// Low-S normalised 64-byte r||s.
pub fn compact_low_s(sig: &Signature) -> [u8; 64] {
    let sig = sig.normalize_s().unwrap_or(*sig);
    sig.to_bytes().into()
}

/// Strips an optional 0x prefix and hex-decodes.
pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?)
}

/// 0x-prefixed lowercase hex.
pub fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// The file `bbc-sign` writes and `bbc-submit` reads. Public data only: it carries no secret,
/// and it can only ever pay the recipient written inside it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignedRecovery {
    pub bbc_address: String,
    pub chain_id: String,
    pub token_symbol: String,
    pub amount_base_units: u64,
    pub recipient: String,
    pub message_to_sign: String,
    /// 0x + 33-byte compressed secp256k1 public key.
    pub public_key: String,
    /// 0x + 64-byte r||s, low-S.
    pub signature: String,
    pub derivation_path: String,
    pub signed_with: String,
}

impl SignedRecovery {
    /// Assembles the file contents and checks them.
    pub fn new(
        req: &RecoveryRequest,
        pubkey: &[u8],
        sig64: &[u8],
        derivation_path: String,
        signed_with: &str,
    ) -> Result<Self> {
        let s = Self {
            bbc_address: req.bbc_address.clone(),
            chain_id: CHAIN_ID.to_string(),
            token_symbol: req.token_symbol.clone(),
            amount_base_units: req.amount_base_units,
            recipient: req.recipient.to_checksum(None),
            message_to_sign: req.message()?,
            public_key: encode_hex(pubkey),
            signature: encode_hex(sig64),
            derivation_path,
            signed_with: signed_with.to_string(),
        };
        s.check()?;
        Ok(s)
    }

    /// Full independent check of the file: every field is re-validated, the message is rebuilt
    /// from the fields and compared byte for byte, the public key must derive `bbc_address`, and
    /// the signature must verify. Returns the validated request.
    pub fn check(&self) -> Result<RecoveryRequest> {
        if self.chain_id != CHAIN_ID {
            return Err(Error::Mismatch(format!("chain_id is {}, expected {CHAIN_ID}", self.chain_id)));
        }
        validate_symbol(&self.token_symbol)?;
        if self.amount_base_units == 0 {
            return Err(Error::BadAmount("0".into()));
        }
        let req = RecoveryRequest {
            bbc_address: parse_bbc_address(&self.bbc_address)?,
            token_symbol: self.token_symbol.clone(),
            amount_base_units: self.amount_base_units,
            recipient: parse_recipient(&self.recipient)?,
        };
        if req.bbc_address != self.bbc_address {
            return Err(Error::Mismatch(format!("bbc_address {} is not in canonical lowercase form", self.bbc_address)));
        }
        let want_msg = req.message()?;
        if self.message_to_sign != want_msg {
            return Err(Error::Mismatch(format!(
                "message_to_sign does not match the fields: file has {}, fields give {want_msg}",
                self.message_to_sign
            )));
        }
        let pubkey = decode_hex(&self.public_key)?;
        let derived = bbc_address(&pubkey)?;
        if derived != req.bbc_address {
            return Err(Error::Mismatch(format!(
                "public_key derives {derived}, not {} (signed with the wrong key or path)",
                req.bbc_address
            )));
        }
        let sig = decode_hex(&self.signature)?;
        if sig.len() != 64 {
            return Err(Error::BadSignature(format!("expected 64 bytes, got {}", sig.len())));
        }
        verify_signature(self.message_to_sign.as_bytes(), &pubkey, &sig)?;
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Worked example from the official tool's README
    // (github.com/bnb-chain/token-recover-self-service-tools, a team-controlled test wallet).
    const README_BBC: &str = "bnb1nn3h8hm678shs5vxj8a5enjes0uhf7nwf0wq4m";
    const README_TO: &str = "0x441DE55A37F6C381b00Db8B52DF8f57794784a1A";
    const README_MSG: &str = r#"{"account_number":"0","chain_id":"Binance-Chain-Tigris","data":null,"memo":"","msgs":[{"amount":"00000000000000000000000000000000000000000000000000000000000003e8","recipient":"0x441de55a37f6c381b00db8b52df8f57794784a1a","token_symbol":"43414b452d343335000000000000000000000000000000000000000000000000"}],"sequence":"0","source":"0"}"#;
    const README_PUB: &str = "0x030771d42cc0a93289bf457e575bdb42c0d56fcf5953df6614b1b7de2986ce941c";
    const README_SIG: &str = "0xe4838ff411975a210cb15d5c950b53835f5d5bb7b0ebb8dbc4515541bb01181e408f7cbbdab08c9278a623667909e8c3c39fee8c3df65de65df4aec0c48f4196";

    fn readme_request() -> RecoveryRequest {
        RecoveryRequest::parse(README_BBC, "CAKE-435", "0.00001", README_TO).unwrap()
    }

    #[test]
    fn sign_bytes_match_official_readme() {
        let req = readme_request();
        assert_eq!(req.amount_base_units, 1000);
        assert_eq!(req.message().unwrap(), README_MSG);
    }

    #[test]
    fn readme_pubkey_derives_readme_address() {
        assert_eq!(bbc_address(&decode_hex(README_PUB).unwrap()).unwrap(), README_BBC);
    }

    #[test]
    fn readme_signature_verifies_and_tampering_fails() {
        let pk = decode_hex(README_PUB).unwrap();
        let sig = decode_hex(README_SIG).unwrap();
        verify_signature(README_MSG.as_bytes(), &pk, &sig).unwrap();
        assert!(verify_signature(README_MSG.replace("03e8", "03e9").as_bytes(), &pk, &sig).is_err());
    }

    #[test]
    fn signed_file_round_trip_and_tampering() {
        let req = readme_request();
        let pk = decode_hex(README_PUB).unwrap();
        let sig = decode_hex(README_SIG).unwrap();
        let signed = SignedRecovery::new(&req, &pk, &sig, "m/44'/714'/0'/0/0".into(), "test").unwrap();
        assert_eq!(signed.check().unwrap(), req);

        let mut t = signed.clone();
        t.amount_base_units += 1;
        assert!(t.check().is_err(), "amount changed without re-signing");
        let mut t = signed.clone();
        t.recipient = "0x0000000000000000000000000000000000000001".into();
        assert!(t.check().is_err(), "recipient changed without re-signing");
        let mut t = signed.clone();
        t.bbc_address = "bnb1ddt3ls9fjcd8mh69ujdg3fxc89qle2a7km33aa".into();
        assert!(t.check().is_err(), "address not derived by the public key");
        let mut t = signed;
        t.chain_id = "Binance-Chain-Ganges".into();
        assert!(t.check().is_err(), "testnet chain id");
    }

    /// Independent re-implementation of the contract's `_tmSignatureHash` preimage (string
    /// concatenation, exactly as in TokenRecoverPortal.sol), for a native-BNB request.
    #[test]
    fn sign_bytes_match_contract_template() {
        let to = parse_recipient(README_TO).unwrap();
        let amount = parse_amount("123.45678901").unwrap();
        let ours = sign_bytes(CHAIN_ID, NATIVE_SYMBOL, amount, &to).unwrap();
        let contract = [
            r#"{"account_number":"0","chain_id":""#,
            CHAIN_ID,
            r#"","data":null,"memo":"","msgs":[{"amount":""#,
            &format!("{amount:064x}"),
            r#"","recipient":""#,
            &format!("0x{}", hex::encode(to.as_slice())),
            r#"","token_symbol":""#,
            &format!("{:0<64}", hex::encode("BNB")),
            r#""}],"sequence":"0","source":"0"}"#,
        ]
        .concat();
        assert_eq!(String::from_utf8(ours).unwrap(), contract);
    }

    #[test]
    fn bbc_payload_matches_pubkey_hash() {
        let pk = decode_hex(README_PUB).unwrap();
        let h160 = Ripemd160::digest(Sha256::digest(&pk));
        assert_eq!(bbc_address_payload(README_BBC).unwrap()[..], h160[..]);
        assert_eq!(hex::encode(bbc_address_payload(README_BBC).unwrap()), "9ce373df7af1e178518691fb4cce5983f974fa6e");
        assert!(bbc_address_payload("tbnb1hgm0p7khfk85zpz5v0j8wnej3a90w709zzlffd").is_err(), "testnet prefix");
        assert!(parse_bbc_address("bnb1nn3h8hm678shs5vxj8a5enjes0uhf7nwf0wq4n").is_err(), "bad checksum");
        assert_eq!(parse_bbc_address(&README_BBC.to_uppercase()).unwrap(), README_BBC, "canonical form");
    }

    #[test]
    fn amounts_parse_exactly() {
        assert_eq!(parse_amount("1").unwrap(), 100_000_000);
        assert_eq!(parse_amount("0.00000001").unwrap(), 1);
        assert_eq!(parse_amount("12.5").unwrap(), 1_250_000_000);
        assert_eq!(parse_amount(" 0.1 ").unwrap(), 10_000_000);
        for bad in ["", "0", "0.0", "-1", "1e5", "1.", ".5", "1.123456789", "1,5", "abc", "184467440737.09551616"] {
            assert!(parse_amount(bad).is_err(), "{bad:?} must be rejected");
        }
        assert_eq!(format_amount(parse_amount("98765.4321").unwrap()), "98765.43210000");
    }

    #[test]
    fn bad_recipients_and_symbols_rejected() {
        assert!(parse_recipient(&README_TO.to_lowercase()).is_err(), "no checksum");
        assert!(parse_recipient(&README_TO.replace("DE55", "de55")).is_err(), "bad checksum");
        assert!(parse_recipient("0x0000000000000000000000000000000000000000").is_err(), "zero");
        assert!(symbol_bytes32(&"A".repeat(32)).is_err());
        assert!(symbol_bytes32("").is_err());
        assert!(symbol_bytes32("BN B").is_err());
        assert_eq!(hex::encode(&symbol_bytes32("BNB").unwrap()[..4]), "424e4200");
    }
}
