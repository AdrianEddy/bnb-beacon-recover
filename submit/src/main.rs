//! bbc-submit: the online half of a BNB Beacon Chain token recovery.
//!
//!   lookup    what the official API lists for a bnb1 address (run this before signing)
//!   approve   re-verify `signed-recovery.json` (from bbc-sign), get the Merkle proof and approval
//!             signature from the official API, simulate `recover()` against the live BSC contract
//!   send      sign `recover()` with the Ledger Ethereum app, save the signed tx, then broadcast it
//!   withdraw  after the 7-day lock, call TokenHub `withdrawUnlockedToken()` the same way, so the
//!             funds do not wait for BNB Chain's withdrawal bot
//!   status    API status, recovered flag, TokenHub lock, saved transactions
//!
//! Files in the current directory. Use one folder per recovery (one bnb1 address + one token):
//!   signed-recovery.json             from bbc-sign (input)
//!   approve-response.json            raw /approve response body (written before parsing)
//!   recover-payload.unverified.json  payload built from the approval, not yet simulated
//!   recover-payload.json             payload that passed simulation
//!   recover-tx.json                  the signed recover() transaction (written before broadcast)
//!   withdraw-tx.json                 the signed withdrawUnlockedToken() transaction (written before broadcast)

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::{
    eips::{BlockNumberOrTag, eip2718::Encodable2718},
    network::{EthereumWallet, NetworkTransactionBuilder, TransactionBuilder},
    primitives::{
        Address, B256, Bytes, U256, address, keccak256,
        utils::{format_ether, format_units, parse_units},
    },
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::{
        Signer,
        ledger::{HDPath, LedgerSigner},
    },
    sol,
    sol_types::{SolCall, SolInterface, decode_revert_reason},
    transports::TransportError,
};
use bbc_core::{NATIVE_SYMBOL, RecoveryRequest, SignedRecovery};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// Official endpoints (bnb-chain/token-recover-self-service-tools).
const API: &str = "https://mainnet-token-recover-api.bnbchain.org";
const BSC_RPC: &str = "https://bsc-dataseed.bnbchain.org";
const BSC_CHAIN_ID: u64 = 56;
const BSCSCAN: &str = "https://bscscan.com";
/// TokenRecoverPortal and TokenHub system contracts on BSC mainnet.
const PORTAL: Address = address!("0000000000000000000000000000000000003000");
const TOKEN_HUB: Address = address!("0000000000000000000000000000000000001004");
/// SECURITY_RECOVER_GAS_LIMIT from the official tool.
const GAS_LIMIT: u64 = 1_000_000;
/// withdrawUnlockedToken() uses ~46k gas for BNB; a BEP20 transfer is capped at 50k gas inside it.
const WITHDRAW_GAS_LIMIT: u64 = 150_000;
/// Refuse an RPC-quoted gas price above this unless overridden (BSC usually quotes ~0.05 gwei).
const MAX_AUTO_GAS_PRICE_WEI: u128 = 1_000_000_000;
const STATUS_PENDING: i64 = 2;
const RECEIPT_WAIT: Duration = Duration::from_secs(180);
/// Hard deadline on any single RPC call (the HTTP client also has a 30 s timeout).
const RPC_DEADLINE: Duration = Duration::from_secs(40);

const APPROVE_RESPONSE: &str = "approve-response.json";
const PAYLOAD_UNVERIFIED: &str = "recover-payload.unverified.json";
const PAYLOAD: &str = "recover-payload.json";
const TX_RECORD: &str = "recover-tx.json";
const WITHDRAW_TX_RECORD: &str = "withdraw-tx.json";

sol! {
    /// bnb-chain/bsc-genesis-contract contracts/TokenRecoverPortal.sol (+ Protectable errors)
    #[sol(all_derives)]
    interface TokenRecoverPortal {
        function recover(
            bytes32 tokenSymbol,
            uint256 amount,
            bytes ownerPubKey,
            bytes ownerSignature,
            bytes approvalSignature,
            bytes32[] merkleProof
        ) external;
        function isRecovered(bytes32 node) external view returns (bool);

        error AlreadyRecovered();
        error InvalidProof();
        error InvalidApprovalSignature();
        error InvalidOwnerPubKeyLength();
        error InvalidOwnerSignatureLength();
        error MerkleRootAlreadyInitiated();
        error MerkleRootNotInitialized();
        error TokenRecoverPortalPaused();
        error ApprovalAddressNotInitialized();
        error AlreadyPaused();
        error NotPaused();
        error InBlackList();
    }

    /// bnb-chain/bsc-genesis-contract contracts/TokenHub.sol
    interface TokenHub {
        function lockInfoMap(address token, address recipient) external view returns (uint256 amount, uint256 unlockAt);
        /// Permissionless after unlockAt; pays the locked amount only to `recipient`.
        function withdrawUnlockedToken(address tokenAddress, address recipient) external;
        function getContractAddrByBEP2Symbol(bytes32 bep2Symbol) external view returns (address);
    }

    interface IBEP20 {
        function decimals() external view returns (uint8);
        function balanceOf(address account) external view returns (uint256);
    }
}

#[derive(Parser)]
#[command(version, about = "Online half of a BNB Beacon Chain token recovery: lookup, approval, simulation, submission, withdrawal")]
struct Cli {
    /// The file written by bbc-sign. Keep one folder per recovery (one bnb1 address + one token).
    #[arg(long, global = true, default_value = "signed-recovery.json")]
    signed: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

/// Which Ledger Ethereum-app path holds the recipient.
#[derive(Args, Clone)]
struct LedgerPath {
    /// Ledger Live account number: path m/44'/60'/<N>'/0/0 (default 0)
    #[arg(long, default_value_t = 0, conflicts_with_all = ["legacy", "path"])]
    ledger_live: usize,
    /// Legacy path m/44'/60'/0'/<N>
    #[arg(long, conflicts_with = "path")]
    legacy: Option<usize>,
    /// Any other path, e.g. "m/44'/60'/0'/0/5"
    #[arg(long)]
    path: Option<String>,
}

impl LedgerPath {
    fn hd_path(&self) -> HDPath {
        match (&self.path, self.legacy) {
            (Some(p), _) => HDPath::Other(p.clone()),
            (None, Some(i)) => HDPath::Legacy(i),
            (None, None) => HDPath::LedgerLive(self.ledger_live),
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// What the official API lists for a Beacon Chain address, and the bbc-sign command to run next
    Lookup {
        /// Beacon Chain address (bnb1...)
        address: String,
    },
    /// Status of the recovery in signed-recovery.json: API, recovered flag, TokenHub lock, saved transactions
    Status,
    /// List BSC addresses on the Ledger Ethereum app with balances (read-only, not shown on device)
    EthAddresses {
        #[arg(long, default_value_t = 5)]
        count: usize,
        /// Also query this exact path
        #[arg(long)]
        path: Option<String>,
    },
    /// Verify signed-recovery.json, get the approval (or reuse a saved payload), simulate
    Approve {
        /// Ignore saved payloads and request a new approval
        #[arg(long)]
        refresh: bool,
        /// Request approval even if the API status is not Pending
        #[arg(long)]
        force: bool,
    },
    /// Simulate recover() against the live contract from the recipient (no transaction sent)
    Simulate,
    /// Sign recover() with the Ledger Ethereum app, save it, then broadcast it
    Send {
        #[command(flatten)]
        ledger: LedgerPath,
        /// Gas price in gwei (overrides the RPC quote and the 1 gwei safety cap)
        #[arg(long)]
        gas_price_gwei: Option<String>,
    },
    /// After the 7-day lock: sign TokenHub withdrawUnlockedToken() with the Ledger, save it, then broadcast it
    Withdraw {
        #[command(flatten)]
        ledger: LedgerPath,
        /// Gas price in gwei (overrides the RPC quote and the 1 gwei safety cap)
        #[arg(long)]
        gas_price_gwei: Option<String>,
        /// Run all checks and the simulation only; do not touch the Ledger
        #[arg(long)]
        dry_run: bool,
    },
    /// Re-broadcast the exact transaction saved in recover-tx.json (same hash, same nonce)
    Rebroadcast {
        /// Re-broadcast withdraw-tx.json instead
        #[arg(long)]
        withdraw: bool,
    },
    /// Simulate, then print the inputs for sending recover() manually via BscScan "Write Contract"
    Bscscan,
}

type Res<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\nERROR: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Res<()> {
    match cli.cmd {
        Cmd::Lookup { address } => return lookup(&address).await,
        Cmd::EthAddresses { count, path } => return eth_addresses(count, path, &cli.signed).await,
        _ => {}
    }
    let rec = load_recovery(&cli.signed)?;
    match cli.cmd {
        Cmd::Status => status(&rec.req).await,
        Cmd::Approve { refresh, force } => approve(&rec, refresh, force).await,
        Cmd::Simulate => {
            let payload = load_payload(Path::new(PAYLOAD), &rec)?;
            simulate(&rpc().await?, &rec.req, &payload).await
        }
        Cmd::Send { ledger, gas_price_gwei } => send(&rec, ledger.hd_path(), gas_price_gwei).await,
        Cmd::Withdraw { ledger, gas_price_gwei, dry_run } => withdraw(&rec.req, ledger.hd_path(), gas_price_gwei, dry_run).await,
        Cmd::Rebroadcast { withdraw } => rebroadcast(&rec.req, if withdraw { Job::Withdraw } else { Job::Recover }).await,
        Cmd::Bscscan => bscscan(&rec).await,
        Cmd::Lookup { .. } | Cmd::EthAddresses { .. } => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// The recovery this folder is about
// ---------------------------------------------------------------------------

/// The verified contents of signed-recovery.json.
struct Recovery {
    signed: SignedRecovery,
    req: RecoveryRequest,
}

fn load_recovery(path: &Path) -> Res<Recovery> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "cannot read {}: {e}. Create it with bbc-sign (`bbc-submit lookup <bnb1 address>` shows the command), \
             or point to it with --signed <file>.",
            path.display()
        )
    })?;
    let signed: SignedRecovery = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let req = signed.check().map_err(|e| format!("{} failed verification: {e}", path.display()))?;
    Ok(Recovery { signed, req })
}

fn print_request(req: &RecoveryRequest) {
    println!("  Beacon Chain address : {}", req.bbc_address);
    println!("  token, amount        : {}", req.amount_display());
    println!("  recipient (BSC)      : {}", req.recipient.to_checksum(None));
}

/// Which transaction a saved record, rebroadcast or outcome analysis is about.
#[derive(Clone, Copy)]
enum Job {
    Recover,
    Withdraw,
}

impl Job {
    fn record(self) -> &'static str {
        match self {
            Job::Recover => TX_RECORD,
            Job::Withdraw => WITHDRAW_TX_RECORD,
        }
    }

    fn command(self) -> &'static str {
        match self {
            Job::Recover => "send",
            Job::Withdraw => "withdraw",
        }
    }

    fn rebroadcast_command(self) -> &'static str {
        match self {
            Job::Recover => "rebroadcast",
            Job::Withdraw => "rebroadcast --withdraw",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Job::Recover => "recover()",
            Job::Withdraw => "withdrawUnlockedToken()",
        }
    }

    fn revert_hint(self) -> &'static str {
        match self {
            Job::Recover => "Nothing was recovered; run `bbc-submit status` and `bbc-submit simulate` to see why.",
            Job::Withdraw => "Nothing was paid out; run `bbc-submit status` and `bbc-submit withdraw --dry-run` to see why.",
        }
    }

    /// On-chain evidence that the job is finished, independent of any receipt.
    async fn done(self, provider: &impl Provider, req: &RecoveryRequest) -> Res<bool> {
        match self {
            Job::Recover => is_recovered(provider, req).await,
            Job::Withdraw => {
                let token = bound_token(provider, &req.token_symbol).await?;
                Ok(lock_info(provider, token.address, req.recipient).await?.0.is_zero())
            }
        }
    }

    fn done_message(self, link: &str, req: &RecoveryRequest) -> String {
        match self {
            Job::Recover => format!(
                "The recovered flag is now SET on-chain, so a recover() tx succeeded (very likely {link}; this node has not \
                 served its receipt yet). Do NOT send again. Run `bbc-submit status`."
            ),
            Job::Withdraw => format!(
                "The TokenHub lock is now EMPTY, so it was paid out (very likely by {link}; this node has not served its \
                 receipt yet) or cancelled. Do NOT run `withdraw` again. Check {BSCSCAN}/address/{} and run \
                 `bbc-submit status`.",
                req.recipient
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// BSC helpers
// ---------------------------------------------------------------------------

async fn rpc() -> Res<impl Provider> {
    // Explicit client: alloy's default reqwest client has no timeout, so a stalled RPC could hang forever.
    let provider = ProviderBuilder::new().connect_reqwest(http()?, BSC_RPC.parse().map_err(err)?);
    let chain = provider.get_chain_id().await.map_err(|e| format!("BSC RPC error: {e}"))?;
    if chain != BSC_CHAIN_ID {
        return Err(format!("RPC chain id {chain} != {BSC_CHAIN_ID}"));
    }
    Ok(provider)
}

/// Merkle leaf the contract marks as recovered:
/// keccak256(abi.encodePacked(ownerAddr(20), tokenSymbol(32), amount(32))).
fn leaf(req: &RecoveryRequest) -> Res<B256> {
    let mut buf = Vec::with_capacity(84);
    buf.extend_from_slice(&bbc_core::bbc_address_payload(&req.bbc_address).map_err(err)?);
    buf.extend_from_slice(&bbc_core::symbol_bytes32(&req.token_symbol).map_err(err)?);
    buf.extend_from_slice(&bbc_core::amount_bytes32(req.amount_base_units));
    Ok(keccak256(buf))
}

async fn view_call(provider: &impl Provider, to: Address, data: Vec<u8>) -> Res<Bytes> {
    let tx = TransactionRequest::default().with_to(to).with_input(data);
    provider.call(tx).latest().await.map_err(|e| format!("eth_call to {to} failed: {e}"))
}

async fn is_recovered(provider: &impl Provider, req: &RecoveryRequest) -> Res<bool> {
    let data = TokenRecoverPortal::isRecoveredCall { node: leaf(req)? }.abi_encode();
    let out = view_call(provider, PORTAL, data).await?;
    TokenRecoverPortal::isRecoveredCall::abi_decode_returns(&out).map_err(err)
}

/// The BSC side of a Beacon Chain token in TokenHub.
#[derive(Clone, Copy)]
struct BscToken {
    /// address(0) for native BNB, otherwise the bound BEP20 contract.
    address: Address,
    decimals: u8,
}

impl BscToken {
    fn format(&self, amount: U256) -> String {
        format_units(amount, self.decimals).unwrap_or_else(|_| amount.to_string())
    }

    fn describe(&self) -> String {
        if self.address.is_zero() { "native BNB".into() } else { format!("BEP20 contract {}", self.address) }
    }
}

/// None when the symbol is not bound to a BSC contract.
async fn bsc_token(provider: &impl Provider, symbol: &str) -> Res<Option<BscToken>> {
    if symbol == NATIVE_SYMBOL {
        return Ok(Some(BscToken { address: Address::ZERO, decimals: 18 }));
    }
    let symbol32 = B256::from(bbc_core::symbol_bytes32(symbol).map_err(err)?);
    let call = TokenHub::getContractAddrByBEP2SymbolCall { bep2Symbol: symbol32 };
    let out = view_call(provider, TOKEN_HUB, call.abi_encode()).await?;
    let address = TokenHub::getContractAddrByBEP2SymbolCall::abi_decode_returns(&out).map_err(err)?;
    if address.is_zero() {
        return Ok(None);
    }
    let out = view_call(provider, address, IBEP20::decimalsCall {}.abi_encode()).await?;
    let decimals = IBEP20::decimalsCall::abi_decode_returns(&out).map_err(err)?;
    Ok(Some(BscToken { address, decimals }))
}

/// TokenHub's `recoverBCAsset` only emits `NotBoundToken` for an unbound symbol: the claim would be
/// marked as used and nothing locked. Every path that sends or withdraws goes through this check.
async fn bound_token(provider: &impl Provider, symbol: &str) -> Res<BscToken> {
    bsc_token(provider, symbol).await?.ok_or_else(|| {
        format!(
            "{symbol} is not bound to a BSC token contract. recover() would mark the claim as used without locking any \
             tokens, so this tool refuses to continue. (The official API lists such tokens as NotBounded.)"
        )
    })
}

async fn lock_info(provider: &impl Provider, token: Address, recipient: Address) -> Res<(U256, U256)> {
    let data = TokenHub::lockInfoMapCall { token, recipient }.abi_encode();
    let out = view_call(provider, TOKEN_HUB, data).await?;
    let r = TokenHub::lockInfoMapCall::abi_decode_returns(&out).map_err(err)?;
    Ok((r.amount, r.unlockAt))
}

async fn token_balance(provider: &impl Provider, token: Address, holder: Address) -> Res<U256> {
    if token.is_zero() {
        return provider.get_balance(holder).await.map_err(err);
    }
    let out = view_call(provider, token, IBEP20::balanceOfCall { account: holder }.abi_encode()).await?;
    IBEP20::balanceOfCall::abi_decode_returns(&out).map_err(err)
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn explain_call_error(e: &TransportError) -> String {
    let Some(resp) = e.as_error_resp() else {
        return format!("RPC/transport error (NOT a contract revert, nothing was decided on-chain): {e}");
    };
    // Revert data independent of the message's wording or casing (alloy's helper only looks when the
    // message contains the lowercase word "revert"; BSC returns e.g. `"data":"0x..."` with code 3).
    let data = resp
        .as_revert_data()
        .or_else(|| serde_json::from_str::<String>(resp.data.as_ref()?.get()).ok()?.parse::<Bytes>().ok())
        .filter(|d| !d.is_empty());
    let is_revert = resp.code == 3 || resp.message.to_ascii_lowercase().contains("revert") || data.is_some();
    if !is_revert {
        return format!("RPC error {} (NOT a contract revert): {}", resp.code, resp.message);
    }
    let Some(data) = data else {
        return format!(
            "contract REVERTED without data ({}). Possible causes in recover(): precompile 0x69 rejected the owner \
             signature/public key, or the sender is not the recipient signed into the message.",
            resp.message
        );
    };
    if let Ok(decoded) = TokenRecoverPortal::TokenRecoverPortalErrors::abi_decode(&data) {
        let hint = match decoded {
            TokenRecoverPortal::TokenRecoverPortalErrors::AlreadyRecovered(_) => {
                " - this claim is already recovered. If you sent a recover tx earlier, it SUCCEEDED; run `bbc-submit status`."
            }
            TokenRecoverPortal::TokenRecoverPortalErrors::AlreadyPaused(_)
            | TokenRecoverPortal::TokenRecoverPortalErrors::TokenRecoverPortalPaused(_) => {
                " - the recovery portal is paused by BNB Chain; wait and retry later."
            }
            _ => "",
        };
        return format!("contract REVERTED: {decoded:?}{hint}");
    }
    match decode_revert_reason(&data) {
        Some(reason) => format!("contract REVERTED: {reason}"),
        None => format!("contract REVERTED with undecoded data {data} ({})", resp.message),
    }
}

// ---------------------------------------------------------------------------
// Official recovery API
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
struct ApiToken {
    symbol: String,
    amount: String,
    status: i64,
    #[serde(default)]
    recipient_address: Option<String>,
    #[serde(default)]
    unlock_at: Option<i64>,
}

#[derive(Deserialize)]
struct ApiList {
    #[serde(default)]
    data: Option<Vec<ApiToken>>,
}

#[derive(Deserialize)]
struct ApiTokenResp {
    data: ApiToken,
}

#[derive(Serialize)]
struct ApproveReq<'a> {
    token_symbol: &'a str,
    owner_pub_key: &'a str,
    owner_signature: &'a str,
    claim_address: &'a str,
}

#[derive(Deserialize)]
struct ApproveResp {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<ApproveData>,
}

#[derive(Deserialize)]
struct ApproveData {
    amount: serde_json::Number,
    proofs: Vec<String>,
    approval_signature: String,
}

fn status_name(s: i64) -> &'static str {
    match s {
        1 => "NotBounded (cannot be recovered)",
        2 => "Pending (ready to recover)",
        3 => "Requested",
        4 => "Locked (7-day on-chain lock; then `bbc-submit withdraw`, or BNB Chain's bot ~23 days later)",
        5 => "Withdrawing",
        6 => "Unlocked (delivered)",
        7 => "Cancelled",
        _ => "unknown",
    }
}

fn http() -> Res<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("bbc-submit/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(err)
}

async fn get_text(url: &str) -> Res<String> {
    let resp = http()?.get(url).send().await.map_err(err)?;
    let status = resp.status();
    let body = resp.text().await.map_err(err)?;
    if !status.is_success() {
        return Err(format!("GET {url} -> HTTP {status}: {body}"));
    }
    Ok(body)
}

async fn api_token(req: &RecoveryRequest) -> Res<ApiToken> {
    let body = get_text(&format!("{API}/api/recover/token/{}?symbol={}", req.bbc_address, req.token_symbol)).await?;
    Ok(serde_json::from_str::<ApiTokenResp>(&body).map_err(|e| format!("{e}: {body}"))?.data)
}

fn print_token(t: &ApiToken) {
    println!("  symbol    : {}", t.symbol);
    println!("  amount    : {}", t.amount);
    println!("  status    : {} = {}", t.status, status_name(t.status));
    if let Some(r) = t.recipient_address.as_deref().filter(|r| !r.is_empty()) {
        println!("  recipient : {r}");
    }
    if let Some(u) = t.unlock_at.filter(|u| *u > 0) {
        let hours = (u - now_unix()) / 3600;
        if hours >= 0 {
            println!("  unlock_at : {u} (unix), {hours} hours from now");
        } else {
            println!("  unlock_at : {u} (unix), {} hours ago", -hours);
        }
    }
}

// ---------------------------------------------------------------------------
// Payload and transaction records
// ---------------------------------------------------------------------------

/// Parameters of `recover()`, in the same shape as the official tool's "Recover Payload".
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoverPayload {
    recipient: String,
    token_symbol: B256,
    amount: U256,
    owner_pub_key: Bytes,
    owner_signature: Bytes,
    approval_signature: Bytes,
    merkle_proof: Vec<B256>,
}

impl RecoverPayload {
    fn calldata(&self) -> Bytes {
        TokenRecoverPortal::recoverCall {
            tokenSymbol: self.token_symbol,
            amount: self.amount,
            ownerPubKey: self.owner_pub_key.clone(),
            ownerSignature: self.owner_signature.clone(),
            approvalSignature: self.approval_signature.clone(),
            merkleProof: self.merkle_proof.clone(),
        }
        .abi_encode()
        .into()
    }

    /// Cross-checks the payload against the verified signed file.
    fn check(&self, rec: &Recovery) -> Res<()> {
        let req = &rec.req;
        if bbc_core::parse_recipient(&self.recipient).map_err(err)? != req.recipient {
            return Err(format!("payload recipient {} != signed recipient {}", self.recipient, req.recipient));
        }
        if self.token_symbol != B256::from(bbc_core::symbol_bytes32(&req.token_symbol).map_err(err)?) {
            return Err("payload tokenSymbol does not match the signed file".into());
        }
        if self.amount != U256::from(req.amount_base_units) {
            return Err("payload amount does not match the signed file".into());
        }
        if self.owner_pub_key.len() != 33 || self.owner_signature.len() != 64 || self.approval_signature.len() != 65 {
            return Err("payload has wrong key/signature lengths".into());
        }
        let key = bbc_core::decode_hex(&rec.signed.public_key).map_err(err)?;
        let sig = bbc_core::decode_hex(&rec.signed.signature).map_err(err)?;
        if self.owner_pub_key.as_ref() != key.as_slice() || self.owner_signature.as_ref() != sig.as_slice() {
            return Err("payload was built from a different signature; move it away or run `approve --refresh`".into());
        }
        if self.merkle_proof.is_empty() {
            return Err("payload merkleProof is empty".into());
        }
        Ok(())
    }
}

fn load_payload(path: &Path, rec: &Recovery) -> Res<RecoverPayload> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e} (run `bbc-submit approve` first)", path.display()))?;
    let p: RecoverPayload = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    p.check(rec).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(p)
}

fn write_json(path: &str, value: &impl Serialize) -> Res<()> {
    let text = serde_json::to_string_pretty(value).map_err(err)? + "\n";
    std::fs::write(path, text).map_err(|e| format!("cannot write {path}: {e}"))
}

/// A signed transaction, saved before it is broadcast.
#[derive(Serialize, Deserialize)]
struct TxRecord {
    hash: B256,
    raw: Bytes,
    from: Address,
    nonce: u64,
    gas_price_wei: String,
    signed_at_unix: i64,
    /// The recovery it belongs to.
    bbc_address: String,
    token_symbol: String,
}

impl TxRecord {
    fn belongs_to(&self, req: &RecoveryRequest) -> bool {
        self.bbc_address == req.bbc_address && self.token_symbol == req.token_symbol && self.from == req.recipient
    }
}

fn read_tx_record(path: &str, req: &RecoveryRequest) -> Res<Option<TxRecord>> {
    let rec: TxRecord = match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {path}: {e}")),
    };
    if !rec.belongs_to(req) {
        return Err(format!(
            "{path} belongs to a different recovery ({} of {}, sent from {}). Use one folder per recovery.",
            rec.token_symbol, rec.bbc_address, rec.from
        ));
    }
    Ok(Some(rec))
}

// ---------------------------------------------------------------------------
// Read-only commands
// ---------------------------------------------------------------------------

async fn lookup(address: &str) -> Res<()> {
    let address = bbc_core::parse_bbc_address(address).map_err(err)?;
    let body = get_text(&format!("{API}/api/recover/list/{address}?limit=1000&offset=0")).await?;
    let list = serde_json::from_str::<ApiList>(&body).map_err(|e| format!("cannot parse API response: {e}: {body}"))?;
    let tokens = list.data.unwrap_or_default();
    if tokens.is_empty() {
        println!("The official recovery API lists nothing for {address}.");
        return Ok(());
    }
    println!("The official recovery API lists for {address}:\n");
    for t in &tokens {
        print_token(t);
        println!();
    }
    let pending: Vec<_> = tokens.iter().filter(|t| t.status == STATUS_PENDING).collect();
    if pending.is_empty() {
        println!("Nothing is in the Pending (ready to recover) state.");
        return Ok(());
    }
    println!("Next, sign each Pending token (one folder per token). Replace <YOUR_BSC_ADDRESS> with your BSC address in");
    println!("EIP-55 mixed case: it receives the funds and must also send the recover transaction.\n");
    for t in pending {
        println!(
            "  bbc-sign ledger-sign --address {address} --token {} --amount {} --recipient <YOUR_BSC_ADDRESS>",
            t.symbol, t.amount
        );
    }
    println!("\n(mnemonic-sign and key-sign take the same arguments; use those on an offline machine only)");
    Ok(())
}

/// Best-effort: every section is independent, so an API or RPC outage never hides the others.
async fn status(req: &RecoveryRequest) -> Res<()> {
    println!("Recovery in this folder:");
    print_request(req);

    println!("\nOfficial API status:");
    match api_token(req).await {
        Ok(t) => print_token(&t),
        Err(e) => println!("  (API unavailable: {e})"),
    }

    println!("\nOn-chain (BSC, latest block):");
    let provider = match rpc().await {
        Ok(p) => p,
        Err(e) => {
            println!("  (BSC RPC unavailable: {e}); check {BSCSCAN}/address/{} instead", req.recipient);
            return Ok(());
        }
    };
    match is_recovered(&provider, req).await {
        Ok(r) => println!("  recovered flag for this claim : {r}"),
        Err(e) => println!("  recovered flag: query failed: {e}"),
    }
    let token = match bsc_token(&provider, &req.token_symbol).await {
        Ok(Some(t)) => {
            println!("  BSC token                     : {}", t.describe());
            Some(t)
        }
        Ok(None) => {
            println!("  BSC token                     : NOT BOUND ({} cannot be recovered with this tool)", req.token_symbol);
            None
        }
        Err(e) => {
            println!("  BSC token: query failed: {e}");
            None
        }
    };
    if let Some(token) = token {
        match lock_info(&provider, token.address, req.recipient).await {
            Ok((amount, unlock_at)) => {
                println!("  TokenHub lock for the recipient: {} {}", token.format(amount), req.token_symbol);
                if !unlock_at.is_zero() {
                    let unlock = i64::try_from(unlock_at).unwrap_or(i64::MAX);
                    let hours = (unlock - now_unix()) / 3600;
                    if amount.is_zero() {
                        println!("    lock is empty: paid out (or cancelled); see {BSCSCAN}/address/{}", req.recipient);
                    } else if unlock <= now_unix() {
                        println!("    UNLOCKED since {unlock} (unix), {} hours ago: `bbc-submit withdraw` can claim it now", -hours);
                    } else {
                        println!("    unlockAt {unlock} (unix), {hours} hours from now; then `bbc-submit withdraw` (or the bot ~23 days later)");
                    }
                }
            }
            Err(e) => println!("  TokenHub lock: query failed: {e}"),
        }
    }
    match (
        provider.get_transaction_count(req.recipient).latest().await,
        provider.get_transaction_count(req.recipient).pending().await,
    ) {
        (Ok(l), Ok(p)) => println!("  recipient nonce: latest {l}, pending {p}{}", if p > l { "  (a tx is PENDING)" } else { "" }),
        (Err(e), _) | (_, Err(e)) => println!("  nonce query failed: {e}"),
    }
    for job in [Job::Recover, Job::Withdraw] {
        match read_tx_record(job.record(), req) {
            Ok(Some(rec)) => {
                println!("  saved {} tx {} (nonce {}): {BSCSCAN}/tx/{}", job.name(), rec.hash, rec.nonce, rec.hash);
                match provider.get_transaction_receipt(rec.hash).await {
                    Ok(Some(r)) => println!("    mined in block {:?}, status {}", r.block_number, if r.status() { "SUCCESS" } else { "REVERTED" }),
                    Ok(None) => println!("    no receipt (pending, dropped, or not yet seen by this RPC node)"),
                    Err(e) => println!("    receipt query failed: {e}"),
                }
            }
            Ok(None) => {}
            Err(e) => println!("  {e}"),
        }
    }
    Ok(())
}

async fn eth_addresses(count: usize, path: Option<String>, signed: &Path) -> Res<()> {
    println!("Open the Ethereum app on the Ledger (close Ledger Live). Addresses are read, not shown on the device.");
    let signer = LedgerSigner::new(HDPath::LedgerLive(0), Some(BSC_CHAIN_ID)).await.map_err(err)?;
    let provider = rpc().await?;
    let target = load_recovery(signed).ok().map(|r| r.req.recipient);
    let paths = (0..count)
        .map(|i| (format!("--ledger-live {i}  m/44'/60'/{i}'/0/0"), HDPath::LedgerLive(i)))
        .chain((0..count).map(|i| (format!("--legacy {i}       m/44'/60'/0'/{i}"), HDPath::Legacy(i))))
        .chain(path.map(|p| (format!("--path {p}"), HDPath::Other(p))));
    for (label, hd) in paths {
        let addr = signer.get_address_with_path(&hd).await.map_err(err)?;
        let bal = provider.get_balance(addr).await.map_err(err)?;
        let mark = if Some(addr) == target { "  <== RECIPIENT in signed-recovery.json" } else { "" };
        println!("{label:32} {}  {} BNB{mark}", addr.to_checksum(None), format_ether(bal));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Approval and simulation
// ---------------------------------------------------------------------------

async fn approve(rec: &Recovery, refresh: bool, force: bool) -> Res<()> {
    let req = &rec.req;
    println!("PASS: signed file verified (message, bnb1 address, signature):");
    print_request(req);

    let provider = rpc().await?;
    if is_recovered(&provider, req).await? {
        return Err("this claim is already recovered on-chain; nothing to approve. Run `bbc-submit status`.".into());
    }
    let token = bound_token(&provider, &req.token_symbol).await?;
    println!("BSC token: {}", token.describe());

    // Reuse a saved payload rather than asking the API again.
    if !refresh {
        for file in [PAYLOAD, PAYLOAD_UNVERIFIED] {
            if !Path::new(file).exists() {
                continue;
            }
            let payload = load_payload(Path::new(file), rec)?;
            println!("Reusing saved {file} (no new approval request; use --refresh to request again).");
            simulate(&provider, req, &payload).await?;
            if file == PAYLOAD_UNVERIFIED {
                std::fs::rename(PAYLOAD_UNVERIFIED, PAYLOAD).map_err(err)?;
                println!("Promoted to {PAYLOAD}.");
            }
            return Ok(());
        }
    }

    let api = api_token(req).await?;
    println!("\nOfficial API:");
    print_token(&api);
    let api_amount = bbc_core::parse_amount(&api.amount).map_err(err)?;
    if api.symbol != req.token_symbol || api_amount != req.amount_base_units {
        return Err(format!(
            "the API lists {} {}, but the signed file claims {}. Sign again with the exact amount and symbol.",
            api.amount,
            api.symbol,
            req.amount_display()
        ));
    }
    if api.status != STATUS_PENDING {
        if !force {
            return Err(format!(
                "API status is {} ({}), not Pending. Not requesting approval; re-run with --force to request anyway.",
                api.status,
                status_name(api.status)
            ));
        }
        println!("WARNING: status is not Pending; continuing because of --force.");
    }

    let recipient = req.recipient.to_checksum(None);
    let body_req = ApproveReq {
        token_symbol: &req.token_symbol,
        owner_pub_key: &rec.signed.public_key,
        owner_signature: &rec.signed.signature,
        claim_address: &recipient,
    };
    println!("\nRequesting approval from {API}/approve ...");
    let resp = http()?.post(format!("{API}/approve")).json(&body_req).send().await.map_err(err)?;
    let http_status = resp.status();
    let body = resp.text().await.map_err(err)?;
    std::fs::write(APPROVE_RESPONSE, &body).map_err(|e| format!("cannot write {APPROVE_RESPONSE}: {e}"))?;
    println!("Saved the raw response to {APPROVE_RESPONSE} (HTTP {http_status}).");
    if !http_status.is_success() {
        return Err(format!("approval API returned HTTP {http_status}: {body}"));
    }
    let resp: ApproveResp = serde_json::from_str(&body).map_err(|e| format!("cannot parse approval response: {e}"))?;
    if let Some(code) = resp.code.filter(|c| *c != 0) {
        return Err(format!("approval API error code {code}: {}", resp.error.or(resp.message).unwrap_or_default()));
    }
    let data = resp.data.ok_or("approval API returned no data")?;
    if data.amount.as_u64() != Some(req.amount_base_units) {
        return Err(format!("approval amount {} != signed amount {}", data.amount, req.amount_base_units));
    }
    let merkle_proof = data
        .proofs
        .iter()
        .map(|p| p.parse::<B256>().map_err(|e| format!("bad proof element {p}: {e}")))
        .collect::<Res<Vec<_>>>()?;

    let payload = RecoverPayload {
        recipient,
        token_symbol: B256::from(bbc_core::symbol_bytes32(&req.token_symbol).map_err(err)?),
        amount: U256::from(req.amount_base_units),
        owner_pub_key: bbc_core::decode_hex(&rec.signed.public_key).map_err(err)?.into(),
        owner_signature: bbc_core::decode_hex(&rec.signed.signature).map_err(err)?.into(),
        approval_signature: bbc_core::decode_hex(&data.approval_signature).map_err(err)?.into(),
        merkle_proof,
    };
    payload.check(rec)?;
    write_json(PAYLOAD_UNVERIFIED, &payload)?;
    println!("Approval received ({} proof elements). Wrote {PAYLOAD_UNVERIFIED}.", payload.merkle_proof.len());

    simulate(&provider, req, &payload).await?;
    std::fs::rename(PAYLOAD_UNVERIFIED, PAYLOAD).map_err(err)?;
    println!("Wrote {PAYLOAD} (simulation passed).");
    println!("Next: bbc-submit send   (Ledger Ethereum app)   or   bbc-submit bscscan   (manual)");
    Ok(())
}

async fn simulate(provider: &impl Provider, req: &RecoveryRequest, payload: &RecoverPayload) -> Res<()> {
    bound_token(provider, &req.token_symbol).await?;
    let tx = TransactionRequest::default()
        .with_from(req.recipient)
        .with_to(PORTAL)
        .with_input(payload.calldata())
        .with_gas_limit(GAS_LIMIT);
    println!("\nSimulating recover() at the LATEST block from {} (eth_call, nothing is sent) ...", req.recipient);
    match provider.call(tx.clone()).latest().await {
        Ok(_) => {
            match provider.estimate_gas(tx).latest().await {
                Ok(gas) => println!("PASS: simulation succeeded. Estimated gas: {gas} (limit {GAS_LIMIT})."),
                Err(e) => println!("PASS: simulation succeeded. (Gas estimate unavailable: {e}; the fixed limit {GAS_LIMIT} is used.)"),
            }
            Ok(())
        }
        Err(e) => Err(format!("simulation FAILED: {}", explain_call_error(&e))),
    }
}

// ---------------------------------------------------------------------------
// Signing and broadcasting (shared by send and withdraw)
// ---------------------------------------------------------------------------

/// Latest nonce of `from`, refusing while any of its transactions is still pending.
async fn settled_nonce(provider: &impl Provider, from: Address) -> Res<u64> {
    let latest_nonce = provider.get_transaction_count(from).latest().await.map_err(err)?;
    let pending_nonce = provider.get_transaction_count(from).pending().await.map_err(err)?;
    if pending_nonce != latest_nonce {
        return Err(format!(
            "a transaction from {from} is still pending (nonce latest {latest_nonce}, pending {pending_nonce}). \
             Wait for it and check `bbc-submit status`; do not send again."
        ));
    }
    Ok(latest_nonce)
}

/// Refuses to sign a new transaction while the job's saved one succeeded or is unresolved.
async fn check_saved_tx(provider: &impl Provider, job: Job, latest_nonce: u64, req: &RecoveryRequest) -> Res<()> {
    let record = job.record();
    let Some(prev) = read_tx_record(record, req)? else {
        return Ok(());
    };
    match provider.get_transaction_receipt(prev.hash).await.map_err(err)? {
        Some(r) if r.status() => {
            Err(format!("{record} holds a SUCCESSFUL {} tx {}; run `bbc-submit status`.", job.name(), prev.hash))
        }
        Some(_) => {
            println!("Note: the saved tx {} reverted; a new one will be signed.", prev.hash);
            Ok(())
        }
        None if prev.nonce == latest_nonce => {
            println!(
                "Note: the saved tx {} (nonce {}) is not mined and not pending; the new tx reuses nonce {latest_nonce}, \
                 so at most one of them can ever be mined.",
                prev.hash, prev.nonce
            );
            Ok(())
        }
        // The saved tx's nonce is already used (or the node is inconsistent) but its receipt is not
        // visible: most likely it WAS mined and this RPC node lags. Never sign a different-nonce retry.
        None => Err(format!(
            "the saved tx {} used nonce {}, the account's latest nonce is {latest_nonce}, and no receipt is visible. \
             Check {BSCSCAN}/tx/{} and {BSCSCAN}/address/{}, then run `bbc-submit status` again later. \
             If BscScan shows a DIFFERENT tx used nonce {}, move {record} aside and run `{}` again.",
            prev.hash,
            prev.nonce,
            prev.hash,
            req.recipient,
            prev.nonce,
            job.command()
        )),
    }
}

/// The RPC's gas price, capped at 1 gwei unless `--gas-price-gwei` overrides it (never below the quote).
async fn choose_gas_price(provider: &impl Provider, gas_price_gwei: Option<String>) -> Res<u128> {
    let network_gas_price = provider.get_gas_price().await.map_err(err)?;
    match gas_price_gwei {
        Some(g) => {
            let wei: U256 = parse_units(&g, "gwei").map_err(err)?.into();
            let wei = u128::try_from(wei).map_err(err)?;
            if wei == 0 {
                return Err("--gas-price-gwei must be greater than 0".into());
            }
            // The override exists to raise the price (or to go past the 1 gwei cap); never undercut the network.
            if network_gas_price <= MAX_AUTO_GAS_PRICE_WEI && wei < network_gas_price {
                return Err(format!(
                    "--gas-price-gwei {g} is below the network quote of {} gwei; the tx would be rejected or stuck.",
                    format_units(network_gas_price, "gwei").map_err(err)?
                ));
            }
            Ok(wei)
        }
        None if network_gas_price > MAX_AUTO_GAS_PRICE_WEI => Err(format!(
            "RPC quotes {} gwei, above the 1 gwei safety cap. Check {BSCSCAN}/gastracker and pass --gas-price-gwei.",
            format_units(network_gas_price, "gwei").map_err(err)?
        )),
        None => Ok(network_gas_price),
    }
}

/// Refuses if `from` cannot cover `max_fee` in BNB.
async fn ensure_gas_balance(provider: &impl Provider, from: Address, max_fee: U256) -> Res<()> {
    let balance = provider.get_balance(from).await.map_err(err)?;
    if balance < max_fee {
        return Err(format!(
            "{from} has {} BNB; needs at least {} BNB for gas. Send a little BNB (on BSC) to it first.",
            format_ether(balance),
            format_ether(max_fee)
        ));
    }
    Ok(())
}

/// Connects to the Ledger Ethereum app and checks that `path` holds `expected`.
async fn ledger_signer(path: HDPath, expected: Address) -> Res<LedgerSigner> {
    println!("\nOpen the Ethereum app on the Ledger (Settings > Blind signing ON; Ledger Live closed).");
    let signer = LedgerSigner::new(path.clone(), Some(BSC_CHAIN_ID)).await.map_err(err)?;
    if signer.address() != expected {
        return Err(format!(
            "Ledger path {path} is {}, but the recipient is {expected}. Use the matching --ledger-live/--legacy/--path \
             (see `bbc-submit eth-addresses`).",
            signer.address()
        ));
    }
    Ok(signer)
}

fn confirm(word: &str) -> Res<()> {
    print!("Type {word} to continue: ");
    std::io::Write::flush(&mut std::io::stdout()).map_err(err)?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(err)?;
    if line.trim() != word {
        return Err("aborted".into());
    }
    Ok(())
}

/// Signs `tx` on the Ledger, saves the raw transaction and its hash to the job's record file, and
/// only then broadcasts it.
async fn sign_save_broadcast(
    provider: &impl Provider,
    signer: LedgerSigner,
    tx: TransactionRequest,
    job: Job,
    req: &RecoveryRequest,
) -> Res<()> {
    let from = tx.from.ok_or("tx has no from")?;
    let nonce = tx.nonce.ok_or("tx has no nonce")?;
    let gas_price = tx.gas_price.ok_or("tx has no gas price")?;
    println!("Confirm the transaction on the Ledger...");
    let envelope = tx.build(&EthereumWallet::from(signer)).await.map_err(|e| format!("signing failed: {e}"))?;
    let raw = envelope.encoded_2718();
    let hash = keccak256(&raw);

    let record = job.record();
    if Path::new(record).exists() {
        let old = format!("{}.replaced-{}.json", record.trim_end_matches(".json"), now_unix());
        std::fs::rename(record, &old).map_err(err)?;
        println!("Moved the previous {record} to {old}.");
    }
    let rec = TxRecord {
        hash,
        raw: raw.into(),
        from,
        nonce,
        gas_price_wei: gas_price.to_string(),
        signed_at_unix: now_unix(),
        bbc_address: req.bbc_address.clone(),
        token_symbol: req.token_symbol.clone(),
    };
    write_json(record, &rec)?;
    println!("Signed. Saved to {record} BEFORE broadcasting.");
    println!("Tx hash: {hash}\n  {BSCSCAN}/tx/{hash}");
    broadcast(provider, &rec, job, req).await
}

async fn send(rec: &Recovery, path: HDPath, gas_price_gwei: Option<String>) -> Res<()> {
    let req = &rec.req;
    let payload = load_payload(Path::new(PAYLOAD), rec)?;
    let provider = rpc().await?;

    // Pre-checks: never send twice.
    if is_recovered(&provider, req).await? {
        println!("Already recovered on-chain (this claim is marked recovered). Nothing to send.\n");
        return status(req).await;
    }
    let latest_nonce = settled_nonce(&provider, req.recipient).await?;
    check_saved_tx(&provider, Job::Recover, latest_nonce, req).await?;
    simulate(&provider, req, &payload).await?;

    let gas_price = choose_gas_price(&provider, gas_price_gwei).await?;
    let max_fee = U256::from(gas_price) * U256::from(GAS_LIMIT);
    ensure_gas_balance(&provider, req.recipient, max_fee).await?;
    let signer = ledger_signer(path.clone(), req.recipient).await?;

    let gwei = format_units(gas_price, "gwei").map_err(err)?;
    println!("\nAbout to sign on the Ledger and broadcast on BNB Smart Chain (chain id {BSC_CHAIN_ID}):");
    println!("  from      : {}  ({path})", req.recipient);
    println!("  to        : {PORTAL}  (TokenRecoverPortal)");
    println!("  call      : recover({}, {})", req.token_symbol, req.amount_display());
    println!("  claim of  : {}", req.bbc_address);
    println!("  value     : 0 BNB");
    println!("  nonce     : {latest_nonce}");
    println!("  gas       : limit {GAS_LIMIT}, price {gwei} gwei, max fee {} BNB", format_ether(max_fee));
    println!("On the Ledger check: blind-signing warning, To = 0x0000...3000, Amount = 0, Network = BNB / chain 56,");
    println!("max fee about {} BNB.", format_ether(max_fee));
    confirm("SEND")?;

    let tx = TransactionRequest::default()
        .with_from(req.recipient)
        .with_to(PORTAL)
        .with_value(U256::ZERO)
        .with_input(payload.calldata())
        .with_nonce(latest_nonce)
        .with_gas_limit(GAS_LIMIT)
        .with_gas_price(gas_price)
        .with_chain_id(BSC_CHAIN_ID);
    sign_save_broadcast(&provider, signer, tx, Job::Recover, req).await?;
    println!("The 7-day lock starts now. After it, run `bbc-submit withdraw` (or wait ~23 more days for BNB Chain's bot).");
    println!("Keep {} a plain address (no smart-account/EIP-7702 upgrade) until paid.", req.recipient);
    println!("Track progress with: bbc-submit status");
    Ok(())
}

// ---------------------------------------------------------------------------
// Withdrawal after the lock
// ---------------------------------------------------------------------------

fn withdraw_calldata(token: Address, recipient: Address) -> Bytes {
    TokenHub::withdrawUnlockedTokenCall { tokenAddress: token, recipient }.abi_encode().into()
}

async fn simulate_withdraw(provider: &impl Provider, token: Address, recipient: Address) -> Res<()> {
    let tx = TransactionRequest::default()
        .with_from(recipient)
        .with_to(TOKEN_HUB)
        .with_input(withdraw_calldata(token, recipient))
        .with_gas_limit(WITHDRAW_GAS_LIMIT);
    println!("\nSimulating withdrawUnlockedToken() at the LATEST block from {recipient} (eth_call, nothing is sent) ...");
    match provider.call(tx.clone()).latest().await {
        Ok(_) => {
            match provider.estimate_gas(tx).latest().await {
                Ok(gas) => println!("PASS: simulation succeeded. Estimated gas: {gas} (limit {WITHDRAW_GAS_LIMIT})."),
                Err(e) => println!(
                    "PASS: simulation succeeded. (Gas estimate unavailable: {e}; the fixed limit {WITHDRAW_GAS_LIMIT} is used.)"
                ),
            }
            Ok(())
        }
        Err(e) => Err(format!("simulation FAILED: {}", explain_call_error(&e))),
    }
}

async fn withdraw(req: &RecoveryRequest, path: HDPath, gas_price_gwei: Option<String>, dry_run: bool) -> Res<()> {
    let recipient = req.recipient;
    let symbol = &req.token_symbol;
    let provider = rpc().await?;

    if !is_recovered(&provider, req).await? {
        return Err("this claim is not marked recovered on-chain, so nothing is locked yet; run `send` first.".into());
    }
    let token = bound_token(&provider, symbol).await?;
    let (amount, unlock_at) = lock_info(&provider, token.address, recipient).await?;
    if amount.is_zero() {
        println!("The TokenHub lock for {recipient} is empty: already paid out (or cancelled). Nothing to withdraw.\n");
        return status(req).await;
    }
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await
        .map_err(err)?
        .ok_or("RPC returned no latest block")?;
    let chain_now = U256::from(block.header.timestamp);
    if chain_now < unlock_at {
        return Err(format!(
            "still locked: unlockAt {unlock_at}, latest block time {chain_now}, {} hours to go.",
            (unlock_at - chain_now) / U256::from(3600)
        ));
    }
    println!(
        "TokenHub lock for {recipient}: {} {symbol} ({}), unlocked since {unlock_at} (latest block time {chain_now}).",
        token.format(amount),
        token.describe()
    );

    let latest_nonce = settled_nonce(&provider, recipient).await?;
    check_saved_tx(&provider, Job::Withdraw, latest_nonce, req).await?;
    simulate_withdraw(&provider, token.address, recipient).await?;
    if dry_run {
        println!("\nDry run: all checks and the simulation passed. Nothing was signed or sent.");
        return Ok(());
    }

    let gas_price = choose_gas_price(&provider, gas_price_gwei).await?;
    let max_fee = U256::from(gas_price) * U256::from(WITHDRAW_GAS_LIMIT);
    ensure_gas_balance(&provider, recipient, max_fee).await?;
    let balance_before = token_balance(&provider, token.address, recipient).await?;
    let signer = ledger_signer(path.clone(), recipient).await?;

    let gwei = format_units(gas_price, "gwei").map_err(err)?;
    println!("\nAbout to sign on the Ledger and broadcast on BNB Smart Chain (chain id {BSC_CHAIN_ID}):");
    println!("  from      : {recipient}  ({path})");
    println!("  to        : {TOKEN_HUB}  (TokenHub)");
    println!("  call      : withdrawUnlockedToken(tokenAddress = {}, recipient = {recipient})", token.address);
    println!("  pays      : {} {symbol} to {recipient} (the contract can pay no one else)", token.format(amount));
    println!("  value     : 0 BNB");
    println!("  nonce     : {latest_nonce}");
    println!("  gas       : limit {WITHDRAW_GAS_LIMIT}, price {gwei} gwei, max fee {} BNB", format_ether(max_fee));
    println!("On the Ledger check: blind-signing warning, To = 0x0000...1004, Amount = 0, Network = BNB / chain 56,");
    println!("max fee about {} BNB.", format_ether(max_fee));
    confirm("WITHDRAW")?;

    let tx = TransactionRequest::default()
        .with_from(recipient)
        .with_to(TOKEN_HUB)
        .with_value(U256::ZERO)
        .with_input(withdraw_calldata(token.address, recipient))
        .with_nonce(latest_nonce)
        .with_gas_limit(WITHDRAW_GAS_LIMIT)
        .with_gas_price(gas_price)
        .with_chain_id(BSC_CHAIN_ID);
    sign_save_broadcast(&provider, signer, tx, Job::Withdraw, req).await?;

    println!("\nAfter the withdrawal (this RPC node may lag a few seconds):");
    match lock_info(&provider, token.address, recipient).await {
        Ok((left, _)) => println!("  TokenHub lock : {} {symbol}", token.format(left)),
        Err(e) => println!("  TokenHub lock : query failed: {e}"),
    }
    match token_balance(&provider, token.address, recipient).await {
        Ok(bal) => println!("  {symbol} balance : {} (was {})", token.format(bal), token.format(balance_before)),
        Err(e) => println!("  {symbol} balance : query failed: {e}"),
    }
    if token.address.is_zero() {
        println!("  incoming BNB shows under {BSCSCAN}/address/{recipient}#internaltx");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Broadcast, rebroadcast, outcome analysis
// ---------------------------------------------------------------------------

async fn rebroadcast(req: &RecoveryRequest, job: Job) -> Res<()> {
    let record = job.record();
    let rec = read_tx_record(record, req)?.ok_or(format!("no {record} in the current directory"))?;
    let provider = rpc().await?;
    if let Some(r) = provider.get_transaction_receipt(rec.hash).await.map_err(err)? {
        println!("{} is already mined (status {}).", rec.hash, if r.status() { "SUCCESS" } else { "REVERTED" });
        return Ok(());
    }
    if job.done(&provider, req).await? {
        println!("The {} effect is already visible on-chain; nothing to rebroadcast. Run `bbc-submit status`.", job.name());
        return Ok(());
    }
    let latest_nonce = provider.get_transaction_count(rec.from).latest().await.map_err(err)?;
    if latest_nonce > rec.nonce {
        return Err(format!(
            "nonce {} of {} is already used on-chain but {} has no visible receipt, so re-sending these bytes can never \
             succeed. Check {BSCSCAN}/tx/{} and run `bbc-submit status`.",
            rec.nonce, rec.from, rec.hash, rec.hash
        ));
    }
    println!("Re-broadcasting the saved transaction {} (same bytes, same nonce {}).", rec.hash, rec.nonce);
    broadcast(&provider, &rec, job, req).await
}

/// After no receipt was seen: reads the account and contract state and says exactly what is safe next.
async fn outcome_after_timeout(
    provider: &impl Provider,
    rec: &TxRecord,
    broadcast_error: Option<&str>,
    job: Job,
    req: &RecoveryRequest,
) -> String {
    let link = format!("{BSCSCAN}/tx/{}", rec.hash);
    let cmd = job.command();
    let done = job.done(provider, req).await;
    let latest = provider.get_transaction_count(rec.from).latest().await;
    let pending = provider.get_transaction_count(rec.from).pending().await;
    match (done, latest, pending) {
        (Ok(true), _, _) => job.done_message(&link, req),
        (Ok(false), Ok(l), Ok(p)) if l == rec.nonce && p == rec.nonce => format!(
            "The transaction was NOT accepted or was dropped: nonce {n} is still unused and nothing is pending{why}.\n\
             It is SAFE to run `bbc-submit {cmd}` again: it reuses nonce {n}, so at most one of them can ever be mined. \
             If the error said 'underpriced', add --gas-price-gwei with a higher value. `{rb}` only helps after a \
             transient network error.",
            n = rec.nonce,
            why = broadcast_error.map(|e| format!(" (broadcast error: {e})")).unwrap_or_default(),
            rb = job.rebroadcast_command()
        ),
        (Ok(false), Ok(l), Ok(p)) if p > l => format!(
            "OUTCOME UNKNOWN: a transaction from {} is still PENDING (nonce latest {l}, pending {p}). Wait, check {link} \
             and run `bbc-submit status`. Do NOT run `{cmd}` again.",
            rec.from
        ),
        (Ok(false), Ok(l), _) => format!(
            "OUTCOME UNKNOWN: nonce {} is used (latest nonce {l}) but no receipt for {link} is visible and the {} effect \
             is not visible on this node. Check BscScan and run `bbc-submit status` later. Do NOT run `{cmd}` again.",
            rec.nonce,
            job.name()
        ),
        (r, l, p) => format!(
            "OUTCOME UNKNOWN: state queries failed ({:?} / {:?} / {:?}). The signed tx is saved in {}. Check {link} \
             and run `bbc-submit status`. Do NOT run `{cmd}` again until the state is clear.",
            r.err(),
            l.err(),
            p.err(),
            job.record()
        ),
    }
}

/// Broadcasts the saved raw transaction and polls for its receipt. Every outcome after this point is
/// either a mined receipt (success/revert) or an explicit state analysis (`outcome_after_timeout`).
async fn broadcast(provider: &impl Provider, rec: &TxRecord, job: Job, req: &RecoveryRequest) -> Res<()> {
    let link = format!("{BSCSCAN}/tx/{}", rec.hash);
    let mut broadcast_error = None;
    match tokio::time::timeout(RPC_DEADLINE, provider.send_raw_transaction(&rec.raw)).await {
        Ok(Ok(pending)) if *pending.tx_hash() != rec.hash => {
            println!("WARNING: RPC returned hash {} but the local hash is {}.", pending.tx_hash(), rec.hash);
        }
        Ok(Ok(_)) => println!("Broadcast accepted by the RPC."),
        Ok(Err(e)) => {
            // e.g. "already known" after a rebroadcast, or a definitive rejection; the poll + analysis settle it.
            println!("Broadcast returned an error: {e}\nChecking whether the transaction is known anyway...");
            broadcast_error = Some(e.to_string());
        }
        Err(_) => {
            println!("Broadcast request timed out after {} s; checking whether the transaction is known...", RPC_DEADLINE.as_secs());
            broadcast_error = Some("request timed out".into());
        }
    }

    let wait = if broadcast_error.is_some() { Duration::from_secs(30) } else { RECEIPT_WAIT };
    println!("Waiting for the receipt (up to {} s)...", wait.as_secs());
    let deadline = std::time::Instant::now() + wait;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let receipt = match tokio::time::timeout(RPC_DEADLINE, provider.get_transaction_receipt(rec.hash)).await {
            Ok(r) => r,
            Err(_) => {
                println!("  (receipt query timed out, retrying)");
                continue;
            }
        };
        match receipt {
            Ok(Some(r)) if r.status() => {
                println!("SUCCESS: mined in block {:?}. {link}", r.block_number);
                return Ok(());
            }
            Ok(Some(r)) => {
                return Err(format!("transaction REVERTED on-chain in block {:?}: {link}. {}", r.block_number, job.revert_hint()));
            }
            Ok(None) => {}
            Err(e) => println!("  (receipt query error, retrying: {e})"),
        }
    }
    println!("No receipt within {} s. Checking the account and contract state...", wait.as_secs());
    let analysis = tokio::time::timeout(RPC_DEADLINE * 3, outcome_after_timeout(provider, rec, broadcast_error.as_deref(), job, req))
        .await
        .unwrap_or_else(|_| {
            format!(
                "OUTCOME UNKNOWN: the state queries timed out. The signed tx is saved in {}. Check {link} and run \
                 `bbc-submit status`. Do NOT run `{}` again until the state is clear.",
                job.record(),
                job.command()
            )
        });
    Err(analysis)
}

async fn bscscan(rec: &Recovery) -> Res<()> {
    let p = load_payload(Path::new(PAYLOAD), rec)?;
    let provider = rpc().await?;
    simulate(&provider, &rec.req, &p)
        .await
        .map_err(|e| format!("{e}\nNot printing manual inputs for a payload that fails simulation."))?;
    let proof = p.merkle_proof.iter().map(|h| h.to_string()).collect::<Vec<_>>().join(",");
    println!("\nManual route: {BSCSCAN}/address/{PORTAL}#writeContract");
    println!("Connect the wallet holding {} (must be that exact address), then fill `recover`:\n", p.recipient);
    println!("tokenSymbol (bytes32):\n{}\n", p.token_symbol);
    println!("amount (uint256):\n{}\n", p.amount);
    println!("ownerPubKey (bytes):\n{}\n", p.owner_pub_key);
    println!("ownerSignature (bytes):\n{}\n", p.owner_signature);
    println!("approvalSignature (bytes):\n{}\n", p.approval_signature);
    println!("merkleProof (bytes32[]):\n[{proof}]\n");
    println!("Set gas limit to {GAS_LIMIT} in the wallet. Value: 0. Network: BNB Smart Chain.");
    println!("\nRaw calldata (for wallets that accept custom data, to {PORTAL}):\n{}", p.calldata());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Worked example from the official tool's README (a team-controlled test wallet).
    const README_BBC: &str = "bnb1nn3h8hm678shs5vxj8a5enjes0uhf7nwf0wq4m";
    const README_TO: &str = "0x441DE55A37F6C381b00Db8B52DF8f57794784a1A";

    fn readme_request() -> RecoveryRequest {
        RecoveryRequest::parse(README_BBC, "CAKE-435", "0.00001", README_TO).unwrap()
    }

    #[test]
    fn leaf_matches_independent_computation() {
        // keccak256(ownerAddr20 || bytes32("CAKE-435") || uint256(1000)), computed independently with pycryptodome.
        assert_eq!(
            leaf(&readme_request()).unwrap().to_string(),
            "0x9380bd04247d70a415e1262bfa4bc209a5f9e9ed6e947bf8ce727fa4f420df25"
        );
    }

    #[test]
    fn selectors_match_contract() {
        // keccak256 of each signature, computed independently with pycryptodome.
        assert_eq!(hex::encode(TokenRecoverPortal::recoverCall::SELECTOR), "bfb5a6a1");
        assert_eq!(hex::encode(TokenRecoverPortal::isRecoveredCall::SELECTOR), "e33f8d32");
        assert_eq!(hex::encode(TokenHub::withdrawUnlockedTokenCall::SELECTOR), "cf419844");
        assert_eq!(hex::encode(TokenHub::lockInfoMapCall::SELECTOR), "2ae45483");
        assert_eq!(hex::encode(TokenHub::getContractAddrByBEP2SymbolCall::SELECTOR), "59b92789");
        assert_eq!(hex::encode(IBEP20::decimalsCall::SELECTOR), "313ce567");
    }

    #[test]
    fn withdraw_calldata_matches_independent_encoding() {
        let expected = concat!(
            "0xcf419844",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000441de55a37f6c381b00db8b52df8f57794784a1a"
        );
        assert_eq!(withdraw_calldata(Address::ZERO, readme_request().recipient).to_string(), expected);
    }

    #[test]
    fn tx_record_from_another_recovery_is_rejected() {
        let req = readme_request();
        let mut rec = TxRecord {
            hash: B256::ZERO,
            raw: Bytes::new(),
            from: req.recipient,
            nonce: 0,
            gas_price_wei: "0".into(),
            signed_at_unix: 0,
            bbc_address: req.bbc_address.clone(),
            token_symbol: req.token_symbol.clone(),
        };
        assert!(rec.belongs_to(&req));
        rec.token_symbol = "BNB".into();
        assert!(!rec.belongs_to(&req));
    }

    fn rpc_err(code: i64, message: &str, data: Option<&str>) -> TransportError {
        let data = data.map(|d| serde_json::value::RawValue::from_string(format!("\"{d}\"")).unwrap());
        alloy_json_rpc::RpcError::ErrorResp(alloy_json_rpc::ErrorPayload { code, message: message.to_string().into(), data })
    }

    #[test]
    fn classifies_bsc_empty_revert() {
        // Live BSC shape for a precompile/sender rejection.
        let msg = explain_call_error(&rpc_err(3, "execution reverted: 0x", Some("0x")));
        assert!(msg.starts_with("contract REVERTED without data"), "{msg}");
    }

    #[test]
    fn decodes_custom_error_regardless_of_message_casing() {
        let msg = explain_call_error(&rpc_err(3, "Execution Reverted", Some("0xad60149e")));
        assert!(msg.contains("InvalidApprovalSignature"), "{msg}");
        let msg = explain_call_error(&rpc_err(-32000, "something", Some("0x3e493100")));
        assert!(msg.contains("AlreadyRecovered") && msg.contains("SUCCEEDED"), "{msg}");
    }

    #[test]
    fn decodes_error_string() {
        // abi.encodeWithSignature("Error(string)", "insufficient balance")
        let data = concat!(
            "0x08c379a0",
            "0000000000000000000000000000000000000000000000000000000000000020",
            "0000000000000000000000000000000000000000000000000000000000000014",
            "696e73756666696369656e742062616c616e6365000000000000000000000000"
        );
        let msg = explain_call_error(&rpc_err(3, "execution reverted", Some(data)));
        assert!(msg.contains("insufficient balance"), "{msg}");
    }

    #[test]
    fn non_revert_rpc_errors_are_labelled() {
        let msg = explain_call_error(&rpc_err(-32000, "nonce too low", None));
        assert!(msg.contains("NOT a contract revert"), "{msg}");
    }
}
