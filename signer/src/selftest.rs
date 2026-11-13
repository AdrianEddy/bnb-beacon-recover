//! Built-in test vectors, runnable on the signing machine before touching any secret
//! (`bbc-sign selftest`) and as unit tests (`cargo test`). Public test data only.

use crate::keys;

/// Public test mnemonic and expected addresses from the official bnb-chain/go-sdk
/// (keys/keys_test.go, TestRecoveryFromKeyWordsNoError). NOT a real wallet.
const GO_SDK_MNEMONIC: &str = "bottom quick strong ranch section decide pepper broken oven demand coin run jacket curious business achieve mule bamboo remain vote kid rigid bench rubber";
const GO_SDK_VECTORS: [(&str, &str); 2] = [
    ("m/44'/714'/0'/0/0", "bnb1ddt3ls9fjcd8mh69ujdg3fxc89qle2a7km33aa"),
    ("m/44'/714'/1'/1/1", "bnb1c67nwp7u5adl7gw0ffn3d47kttcm4crjy9mrye"),
];

/// Worked example from the official recovery tool's README (a team-controlled test wallet).
const README_MSG: &str = r#"{"account_number":"0","chain_id":"Binance-Chain-Tigris","data":null,"memo":"","msgs":[{"amount":"00000000000000000000000000000000000000000000000000000000000003e8","recipient":"0x441de55a37f6c381b00db8b52df8f57794784a1a","token_symbol":"43414b452d343335000000000000000000000000000000000000000000000000"}],"sequence":"0","source":"0"}"#;
const README_TO: &str = "0x441DE55A37F6C381b00Db8B52DF8f57794784a1A";
const README_PUB: &str = "0x030771d42cc0a93289bf457e575bdb42c0d56fcf5953df6614b1b7de2986ce941c";
const README_SIG: &str = "0xe4838ff411975a210cb15d5c950b53835f5d5bb7b0ebb8dbc4515541bb01181e408f7cbbdab08c9278a623667909e8c3c39fee8c3df65de65df4aec0c48f4196";
const README_BBC: &str = "bnb1nn3h8hm678shs5vxj8a5enjes0uhf7nwf0wq4m";

fn check(name: &str, ok: bool) -> Result<(), String> {
    println!("  [{}] {name}", if ok { "PASS" } else { "FAIL" });
    if ok { Ok(()) } else { Err(format!("self-test failed: {name}")) }
}

pub fn run() -> Result<(), String> {
    use bbc_core::*;
    let e = |e: Error| e.to_string();
    println!("Self-test (public test vectors only, no secrets involved):");

    let req = RecoveryRequest::parse(README_BBC, "CAKE-435", "0.00001", README_TO).map_err(e)?;
    check("sign message construction matches the official README", req.message().map_err(e)? == README_MSG)?;

    let pubkey = decode_hex(README_PUB).map_err(e)?;
    let sig = decode_hex(README_SIG).map_err(e)?;
    check("README public key -> README bnb1 address", bbc_address(&pubkey).ok().as_deref() == Some(README_BBC))?;
    check("README signature verifies", verify_signature(README_MSG.as_bytes(), &pubkey, &sig).is_ok())?;
    check(
        "tampered message is rejected",
        verify_signature(README_MSG.replace("03e8", "03e9").as_bytes(), &pubkey, &sig).is_err(),
    )?;
    let signed = SignedRecovery::new(&req, &pubkey, &sig, "test".into(), "test").map_err(e)?;
    check("signed-file check accepts the README signature", signed.check().is_ok())?;

    let seed = keys::seed_from_phrase(GO_SDK_MNEMONIC, "")?;
    for (path, want) in GO_SDK_VECTORS {
        let key = keys::derive(seed.as_slice(), path)?;
        let got = bbc_address(&keys::compressed_pubkey(key.private_key())).map_err(e)?;
        check(&format!("go-sdk vector {path} -> {want}"), got == want)?;
    }
    let messy = keys::seed_from_phrase(&format!("  {}  ", GO_SDK_MNEMONIC.to_uppercase().replace(' ', "   ")), "")?;
    check("phrase input is case/whitespace-insensitive", messy.as_slice() == seed.as_slice())?;
    let with_pass = keys::seed_from_phrase(GO_SDK_MNEMONIC, "x")?;
    check("passphrase changes the seed", with_pass.as_slice() != seed.as_slice())?;

    let found = keys::find_path(seed.as_slice(), GO_SDK_VECTORS[0].1, 1, 2)?;
    check("path search finds m/44'/714'/0'/0/0", found.as_ref().map(|(p, _)| p.as_str()) == Some(GO_SDK_VECTORS[0].0))?;

    let (_, xprv) = found.ok_or("path search failed")?;
    let key = xprv.private_key();
    let test_pub = keys::compressed_pubkey(key);
    let sig1 = keys::sign(key, README_MSG.as_bytes());
    let sig2 = keys::sign(key, README_MSG.as_bytes());
    check("local signature verifies (low-S, SHA-256)", verify_signature(README_MSG.as_bytes(), &test_pub, &sig1).is_ok())?;
    check("local signature is deterministic (RFC 6979)", sig1 == sig2)?;

    let hex_key = format!("0x{}", hex::encode(key.to_bytes()));
    let parsed = keys::parse_private_key(&hex_key)?;
    check("raw private key input gives the same key", keys::compressed_pubkey(&parsed) == test_pub)?;
    check("malformed private key is rejected", keys::parse_private_key(&hex_key[..60]).is_err())?;

    println!("All self-tests passed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn selftest_passes() {
        super::run().unwrap();
    }
}
