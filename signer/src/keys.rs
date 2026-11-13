//! Software keys: BIP39 phrase -> seed -> BIP32 m/44'/714'/a'/0/i, or a raw private key.
//! Intended for an offline machine only. This module's own buffers (phrase, passphrase, seed,
//! hex key) are wiped on drop, and bip39/k256 wipe their mnemonic and signing keys; some
//! dependency intermediates (e.g. bip39's normalized passphrase copy, bip32's HMAC output) are
//! not explicitly wiped. Treat the secret as exposed and power the machine off afterwards.

use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic};
use k256::ecdsa::{Signature, SigningKey, signature::Signer};
use zeroize::Zeroizing;

/// BIP39 seed from a phrase (case/whitespace-insensitive) and optional passphrase.
pub fn seed_from_phrase(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>, String> {
    let mut lower = Zeroizing::new(phrase.split_whitespace().collect::<Vec<_>>().join(" "));
    lower.make_ascii_lowercase();
    let mnemonic =
        Mnemonic::parse_in(Language::English, lower.as_str()).map_err(|e| format!("invalid recovery phrase: {e}"))?;
    Ok(Zeroizing::new(mnemonic.to_seed(passphrase)))
}

pub fn path_string(account: u32, index: u32) -> String {
    format!("m/44'/714'/{account}'/0/{index}")
}

pub fn derive(seed: &[u8], path: &str) -> Result<XPrv, String> {
    let path: DerivationPath = path.parse().map_err(|e| format!("bad derivation path {path}: {e}"))?;
    XPrv::derive_from_path(seed, &path).map_err(|e| format!("derivation failed: {e}"))
}

/// Searches m/44'/714'/{0..=max_account}'/0/{0..=max_index} for `target`.
pub fn find_path(seed: &[u8], target: &str, max_account: u32, max_index: u32) -> Result<Option<(String, XPrv)>, String> {
    for account in 0..=max_account {
        for index in 0..=max_index {
            let path = path_string(account, index);
            let key = derive(seed, &path)?;
            let addr = bbc_core::bbc_address(&compressed_pubkey(key.private_key())).map_err(|e| e.to_string())?;
            if addr == target {
                return Ok(Some((path, key)));
            }
        }
    }
    Ok(None)
}

/// A raw secp256k1 private key: 64 hex characters, optional 0x prefix.
pub fn parse_private_key(hex_key: &str) -> Result<SigningKey, String> {
    let t = hex_key.trim();
    let t = t.strip_prefix("0x").unwrap_or(t);
    if t.len() != 64 {
        return Err(format!("a private key is 64 hex characters, got {}", t.len()));
    }
    let bytes = Zeroizing::new(hex::decode(t).map_err(|_| "the private key is not valid hex".to_string())?);
    SigningKey::from_slice(&bytes).map_err(|_| "not a valid secp256k1 private key".to_string())
}

pub fn compressed_pubkey(key: &SigningKey) -> [u8; 33] {
    let point = key.verifying_key().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    out
}

/// RFC 6979 deterministic ECDSA over SHA-256(message), low-S, 64-byte r||s.
pub fn sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    let sig: Signature = key.sign(message);
    bbc_core::compact_low_s(&sig)
}
