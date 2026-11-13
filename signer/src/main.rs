//! bbc-sign: produces the Beacon Chain owner signature for a BNB Beacon Chain token recovery.
//!
//! No networking code is compiled into this binary. The only output is `signed-recovery.json`,
//! which holds public data: the parameters, the message, the public key and the signature.
//! That file is the only thing that needs to travel to the online machine.

mod keys;
mod ledger;
mod selftest;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bbc_core::{CHAIN_ID, RecoveryRequest, SignedRecovery};
use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "Offline signer for a BNB Beacon Chain token recovery (contains no network code)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// What to recover. Copy the values from `bbc-submit lookup <bnb1 address>`.
#[derive(Args)]
struct Request {
    /// Beacon Chain address that holds the balance (bnb1...)
    #[arg(long)]
    address: String,
    /// Token symbol exactly as the official API lists it, e.g. BNB or CAKE-435
    #[arg(long)]
    token: String,
    /// Full amount exactly as the official API lists it, e.g. 12.34567890 (partial amounts are not possible)
    #[arg(long)]
    amount: String,
    /// Your BSC address (EIP-55 mixed case). It receives the funds and must send the recover transaction.
    #[arg(long)]
    recipient: String,
}

impl Request {
    fn parse(&self) -> Result<RecoveryRequest, String> {
        RecoveryRequest::parse(&self.address, &self.token, &self.amount, &self.recipient).map_err(err)
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the exact message that will be signed and what the Ledger will display
    Show {
        #[command(flatten)]
        req: Request,
    },
    /// Run built-in public test vectors (no device or secret needed)
    Selftest,
    /// Ledger: find the path of a bnb1 address in the Binance Chain app (read-only)
    LedgerFind {
        /// Beacon Chain address to look for (bnb1...)
        #[arg(long)]
        address: String,
        #[arg(long, default_value_t = 5)]
        max_account: u32,
        #[arg(long, default_value_t = 20)]
        max_index: u32,
    },
    /// Ledger: confirm the address on the device, review and approve the message, write the signature
    LedgerSign {
        #[command(flatten)]
        req: Request,
        /// Account (from ledger-find). Searched automatically if omitted.
        #[arg(long, requires = "index")]
        account: Option<u32>,
        /// Address index (from ledger-find)
        #[arg(long, requires = "account")]
        index: Option<u32>,
        #[arg(long, default_value = "signed-recovery.json")]
        out: PathBuf,
    },
    /// Recovery phrase: derive the key locally and sign. OFFLINE MACHINE ONLY.
    MnemonicSign {
        #[command(flatten)]
        req: Request,
        #[arg(long, default_value_t = 10)]
        max_account: u32,
        #[arg(long, default_value_t = 50)]
        max_index: u32,
        #[arg(long, default_value = "signed-recovery.json")]
        out: PathBuf,
    },
    /// Raw private key (64 hex characters): sign with it. OFFLINE MACHINE ONLY.
    KeySign {
        #[command(flatten)]
        req: Request,
        #[arg(long, default_value = "signed-recovery.json")]
        out: PathBuf,
    },
    /// Re-check an existing signed-recovery.json (message, address, signature)
    Verify {
        #[arg(default_value = "signed-recovery.json")]
        file: PathBuf,
    },
}

fn main() -> ExitCode {
    let result = match Cli::parse().cmd {
        Cmd::Show { req } => req.parse().map(|r| show(&r)),
        Cmd::Selftest => selftest::run(),
        Cmd::LedgerFind { address, max_account, max_index } => bbc_core::parse_bbc_address(&address)
            .map_err(err)
            .and_then(|a| ledger_find(&open_binance_app()?, &a, max_account, max_index))
            .map(|_| ()),
        Cmd::LedgerSign { req, account, index, out } => req.parse().and_then(|r| ledger_sign(&r, account.zip(index), &out)),
        Cmd::MnemonicSign { req, max_account, max_index, out } => {
            req.parse().and_then(|r| mnemonic_sign(&r, max_account, max_index, &out))
        }
        Cmd::KeySign { req, out } => req.parse().and_then(|r| key_sign(&r, &out)),
        Cmd::Verify { file } => verify_file(&file),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\nERROR: {e}");
            ExitCode::FAILURE
        }
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn print_request(req: &RecoveryRequest) {
    println!("Beacon Chain address : {}", req.bbc_address);
    println!("Token                : {}", req.token_symbol);
    println!("Amount               : {} ({} base units)", req.amount_display(), req.amount_base_units);
    println!("Recipient (BSC)      : {}", req.recipient.to_checksum(None));
}

fn show(req: &RecoveryRequest) {
    print_request(req);
    match req.message() {
        Ok(msg) => println!("\nMessage to sign ({} bytes):\n{msg}", msg.len()),
        Err(e) => println!("\nMessage: {e}"),
    }
    print_device_fields(req);
}

/// What the Ledger "Binance Chain" app v2.x displays, so it can be compared on the device.
/// For the mainnet chain id the app hides chain_id/account/sequence/source/data unless Expert
/// mode is on (app-binance tx_display.c `get_subitem_count`), and it hides the empty memo.
fn print_device_fields(req: &RecoveryRequest) {
    let amount_hex = hex::encode(bbc_core::amount_bytes32(req.amount_base_units));
    let symbol_hex = hex::encode(bbc_core::symbol_bytes32(&req.token_symbol).unwrap_or_default());
    println!("\nThe Ledger shows exactly 3 fields (each long value spans several pages):");
    println!("  msgs/amount       : {amount_hex}");
    println!(
        "                      (= {} base units = {}; ends in ...{})",
        req.amount_base_units,
        req.amount_display(),
        &amount_hex[amount_hex.len() - 10..]
    );
    println!("  msgs/recipient    : 0x{}", hex::encode(req.recipient.as_slice()));
    println!("                      ^ SAFETY-CRITICAL: compare all 40 hex characters with your BSC address");
    println!("  msgs/token_symbol : {symbol_hex}");
    println!("                      (= \"{}\" padded with zeros)", req.token_symbol);
    println!("Chain ID ({CHAIN_ID}), Account, Sequence, Source and Data are only shown in Expert mode.");
}

fn write_output(signed: &SignedRecovery, out: &Path) -> Result<(), String> {
    let req = signed.check().map_err(|e| format!("final self-check failed, nothing written: {e}"))?;
    if out.exists() {
        return Err(format!("{} already exists; move it away or pass --out", out.display()));
    }
    let json = serde_json::to_string_pretty(signed).map_err(err)?;
    std::fs::write(out, json + "\n").map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!("\nPASS: signature verified against {} and the message above.", req.bbc_address);
    println!("Wrote {} (public data only: parameters, message, public key, signature).", out.display());
    println!("Carry ONLY this file to the online machine and run there: bbc-submit approve");
    Ok(())
}

fn verify_file(file: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let signed: SignedRecovery = serde_json::from_str(&text).map_err(err)?;
    let req = signed.check().map_err(err)?;
    println!("PASS: {} is a valid signed recovery:", file.display());
    print_request(&req);
    Ok(())
}

// ---------------------------------------------------------------------------
// Ledger mode
// ---------------------------------------------------------------------------

fn open_binance_app() -> Result<ledger::BinanceApp, String> {
    let app = ledger::BinanceApp::connect()?;
    let (name, version) = app.running_app()?;
    println!("Ledger app open: \"{name}\" v{version}");
    if name != "Binance Chain" {
        return Err(format!("expected the \"Binance Chain\" app to be open on the Ledger, found \"{name}\""));
    }
    let (ma, mi, pa) = app.version()?;
    println!("Binance Chain app version: {ma}.{mi}.{pa}");
    Ok(app)
}

fn ledger_find(app: &ledger::BinanceApp, target: &str, max_account: u32, max_index: u32) -> Result<(u32, u32, [u8; 33]), String> {
    let (max_account, max_index) = (max_account.min(ledger::MAX_NODE), max_index.min(ledger::MAX_NODE));
    println!("Searching m/44'/714'/{{0..={max_account}}}'/0/{{0..={max_index}}} for {target} ...");
    for account in 0..=max_account {
        for index in 0..=max_index {
            let (pubkey, device_addr) = app.get_address(account, index)?;
            let computed = bbc_core::bbc_address(&pubkey).map_err(err)?;
            if computed != device_addr {
                return Err(format!("device address {device_addr} does not match the address of its public key {computed}"));
            }
            if computed == target {
                println!("FOUND at {} (account {account}, index {index})", ledger::path_string(account, index));
                return Ok((account, index, pubkey));
            }
            if index == 0 {
                println!("  account {account}, index 0: {computed}");
            }
        }
    }
    Err(format!(
        "{target} not found on this Ledger in the searched range. Is this the right device, or was a passphrase set? \
         Try a larger --max-account/--max-index with ledger-find."
    ))
}

fn ledger_sign(req: &RecoveryRequest, path: Option<(u32, u32)>, out: &Path) -> Result<(), String> {
    let message = req.message().map_err(err)?;
    print_request(req);
    println!();

    let app = open_binance_app()?;
    let (account, index, pubkey) = match path {
        Some((account, index)) => {
            let (pubkey, addr) = app.get_address(account, index)?;
            if bbc_core::bbc_address(&pubkey).map_err(err)? != req.bbc_address || addr != req.bbc_address {
                return Err(format!("{} does not derive {} (device says {addr})", ledger::path_string(account, index), req.bbc_address));
            }
            (account, index, pubkey)
        }
        None => ledger_find(&app, &req.bbc_address, 3, 20)?,
    };
    let path_str = ledger::path_string(account, index);

    println!("\nStep 1/2: confirm the address on the Ledger screen.");
    println!("  It must read: {}", req.bbc_address);
    app.show_address(account, index)?;
    println!("  Address confirmed on device.");

    println!("\nStep 2/2: review the recovery message on the Ledger and approve it.");
    print_device_fields(req);
    println!("\nWaiting for approval on the device...");
    let der = app.sign(account, index, message.as_bytes())?;
    // The DER signature is public data; show it if anything below fails so the cause is visible.
    let der_hint = || format!("raw DER from device: {}", hex::encode(&der));
    let sig = bbc_core::der_to_compact_low_s(&der).map_err(|e| format!("{e}; {}", der_hint()))?;

    let signed = SignedRecovery::new(req, &pubkey, &sig, path_str, "ledger-binance-chain-app")
        .map_err(|e| format!("{e}; {}", der_hint()))?;
    write_output(&signed, out)
}

// ---------------------------------------------------------------------------
// Recovery-phrase and private-key modes
// ---------------------------------------------------------------------------

fn prompt_line(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    std::io::stdout().flush().map_err(err)?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).map_err(err)?;
    Ok(s.trim().to_string())
}

/// Shows what will be authorised and asks the user to confirm the machine is offline.
fn confirm_offline(req: &RecoveryRequest, mode: &str) -> Result<(), String> {
    println!("{mode}");
    println!("Use this only on a machine that is offline (network cable unplugged, Wi-Fi off),");
    println!("ideally one booted from a live USB and powered off afterwards.\n");
    print_request(req);
    println!("\nThe signature will authorise sending {} to {} and nowhere else.", req.amount_display(), req.recipient.to_checksum(None));
    if prompt_line("\nType OFFLINE to confirm this machine is offline and the recipient is yours: ")? != "OFFLINE" {
        return Err("aborted".into());
    }
    Ok(())
}

fn mnemonic_sign(req: &RecoveryRequest, max_account: u32, max_index: u32, out: &Path) -> Result<(), String> {
    let message = req.message().map_err(err)?;
    confirm_offline(req, "RECOVERY-PHRASE MODE")?;

    let phrase = Zeroizing::new(rpassword::prompt_password("Recovery phrase (12/15/18/21/24 words, input hidden): ").map_err(err)?);
    let passphrase =
        Zeroizing::new(rpassword::prompt_password("BIP39 passphrase (only if you set one; else press Enter): ").map_err(err)?);
    let seed = keys::seed_from_phrase(&phrase, &passphrase)?;
    drop(phrase);
    drop(passphrase);

    println!("Searching m/44'/714'/{{0..={max_account}}}'/0/{{0..={max_index}}} for {} ...", req.bbc_address);
    let (path, xprv) = keys::find_path(seed.as_slice(), &req.bbc_address, max_account, max_index)?
        .ok_or_else(|| format!("{} is not derived by this phrase/passphrase in the searched range", req.bbc_address))?;
    drop(seed);
    println!("FOUND at {path}");

    let key = xprv.private_key();
    let signed = SignedRecovery::new(req, &keys::compressed_pubkey(key), &keys::sign(key, message.as_bytes()), path, "recovery-phrase")
        .map_err(err)?;
    drop(xprv);
    write_output(&signed, out)
}

fn key_sign(req: &RecoveryRequest, out: &Path) -> Result<(), String> {
    let message = req.message().map_err(err)?;
    confirm_offline(req, "PRIVATE-KEY MODE")?;

    let hex_key = Zeroizing::new(rpassword::prompt_password("Private key (64 hex characters, input hidden): ").map_err(err)?);
    let key = keys::parse_private_key(&hex_key)?;
    drop(hex_key);
    let pubkey = keys::compressed_pubkey(&key);
    let derived = bbc_core::bbc_address(&pubkey).map_err(err)?;
    if derived != req.bbc_address {
        return Err(format!("this private key belongs to {derived}, not {}", req.bbc_address));
    }
    let signed = SignedRecovery::new(req, &pubkey, &keys::sign(&key, message.as_bytes()), "(raw private key)".into(), "private-key")
        .map_err(err)?;
    write_output(&signed, out)
}
