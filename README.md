# bnb-beacon-recover

Recover BNB and BEP2 tokens that were left on the shut-down **BNB Beacon Chain** (`bnb1…` addresses)
and receive them on **BNB Smart Chain (BSC)**.

There are two small command-line tools that you build yourself from this source. You sign with a
**Ledger** (using its "Binance Chain" app), or with a recovery phrase or private key on an **offline**
computer. The tools use the same on-chain recovery mechanism and the same official BNB Chain services
as BNB Chain's own
[token recovery tool](https://github.com/bnb-chain/token-recover-self-service-tools).

> No binaries are provided. Read the code, build it, and run it. This project is not affiliated with
> BNB Chain or Ledger. Use it at your own risk (see [License](#license)).

## Who this is for

You may need this if:

- you held BNB or BEP2 tokens on a BNB Beacon Chain address (`bnb1…`) and did not move them before the
  Beacon Chain was shut down during BNB Chain Fusion, and
- the official recovery service still lists that balance as claimable (step 1 below shows you this).

BNB Chain took a snapshot of all Beacon Chain balances. You can claim yours on BSC by proving that you own
the old key: you sign a message with it. This project is an alternative to the web-based official tool,
for people who:

- keep the old key on a **Ledger** and want to sign on the device with the Ledger "Binance Chain" app,
  without ever typing the recovery phrase anywhere;
- or have only a **recovery phrase / private key** and want to sign on an offline machine, so that only
  a signed file (public data) ever touches an internet-connected computer;
- and prefer a small tool they can audit and build themselves.

## What it does

| Step | Tool | Network | What happens |
|---|---|---|---|
| 1 | `bbc-submit lookup` | online | Shows what the official recovery API lists for your `bnb1…` address. |
| 2 | `bbc-sign` | **none** (no network code compiled in) | Signs the recovery message with your Beacon Chain key and writes `signed-recovery.json`. |
| 3 | `bbc-submit approve` | online | Verifies the file and gets the Merkle proof and BNB Chain's approval signature from the official API. Simulates the claim on BSC. |
| 4 | `bbc-submit send` | online | Signs and sends the `recover()` transaction with the Ledger Ethereum app, from your BSC address. |
| 5 | (wait) | | The contract locks the funds for **7 days**. |
| 6 | `bbc-submit withdraw` | online | Releases the funds to your BSC address. Without this, BNB Chain's own bot does it about 23 days later. |

`bbc-submit status` shows where a recovery stands at any time.

| Folder | Contents |
|---|---|
| [`core/`](core/src/lib.rs) | Shared, network-free logic: builds the exact message that gets signed, derives addresses, checks signatures. **Review this first.** |
| [`signer/`](signer/src) | `bbc-sign`: Ledger "Binance Chain" app client, recovery phrase and private key signing, built-in self-test. |
| [`submit/`](submit/src/main.rs) | `bbc-submit`: official API client, BSC simulation, Ledger Ethereum-app transaction signing, withdrawal. |

## Important before you start

- **All or nothing.** Each token claim is the full snapshot balance of that token. You can't send a small
  test amount first, because the proof commits to the exact amount.
- **The recipient is signed into the claim and can't be changed later.** The contract also requires the
  `recover()` transaction to be **sent from that recipient address**. So the recipient must be a BSC
  address you can send transactions from. With a Ledger, use an address from the Ledger's Ethereum app
  (the same addresses Ledger Live shows for "BNB Chain" accounts).
- **The recipient needs a little BNB on BSC for gas.** At typical BSC gas prices, `recover()` costs about
  0.00002 BNB and `withdraw` about 0.000005 BNB. If the address is empty, send it about 0.001 BNB (on BSC)
  first.
- **Keep the recipient a plain address until the funds arrive.** Don't "upgrade" it to a smart account
  (EIP-7702 delegation). The BNB payout forwards only 10,000 gas, and code on the recipient can make it fail.
- **During the 7-day lock BNB Chain can cancel a claim** that it considers fraudulent (`cancelTokenRecover`).
  After you withdraw, the funds are yours like any other.
- **Never share a recovery phrase or private key.** BNB Chain and Ledger never ask for them. Ignore anyone
  who offers recovery "help".

## Requirements

- **Rust 1.94 or newer:** install it from [rustup.rs](https://rustup.rs). If you already have Rust, run
  `rustup update`.
- **Ledger route:** a Ledger with the **Binance Chain** app (to sign the claim) and the **Ethereum** app
  (to send BSC transactions). Install both in Ledger Live under *My Ledger*, then **close Ledger Live**
  while using these tools.
- **Linux:** you may need `pkg-config` and `libudev-dev` (Debian/Ubuntu package names) to build, and
  [Ledger's udev rules](https://github.com/LedgerHQ/udev-rules) to talk to the device.

## Build

```sh
git clone https://github.com/AdrianEddy/bnb-beacon-recover
cd bnb-beacon-recover
cargo test --release --locked
cargo build --release --locked
```

The binaries are `target/release/bbc-sign` and `target/release/bbc-submit` (`.exe` on Windows). The
examples below call them `bbc-sign` and `bbc-submit`. Either add `target/release` to your `PATH` or use the
full path. On Windows the C runtime is linked statically, so `bbc-sign.exe` also runs on a clean offline
machine.

Check the build before you use any secret:

```sh
bbc-sign selftest                    # official README and go-sdk test vectors
cargo tree -p bbc-sign -e normal     # bbc-sign has no HTTP or socket dependencies
```

## Step by step

**Use a new, empty folder for each recovery** (one `bnb1…` address and one token). The tools read and
write their files in the current folder. Run every command below from inside that folder.

### 1. See what you can claim

```sh
bbc-submit lookup bnb1youraddress...
```

It lists every token the official API holds for the address, each with its amount and status. For each
token in the **Pending** state it prints the exact `bbc-sign` command to run next. Copy the amount exactly
as printed; it must be the full amount.

### 2. Choose the recipient (your BSC address)

With a Ledger, open the **Ethereum** app and run:

```sh
bbc-submit eth-addresses
```

This lists the addresses and BSC balances for Ledger Live accounts (`--ledger-live N`) and legacy paths
(`--legacy N`). Nothing is shown or signed on the device. Pick one and copy it **in mixed case**, exactly
as printed (the EIP-55 checksum protects against typos).

### 3. Sign the claim

Preview what will be signed and what the Ledger will display:

```sh
bbc-sign show --address bnb1... --token BNB --amount 12.34567890 --recipient 0xYourBscAddress
```

#### With a Ledger

Open the **Binance Chain** app on the Ledger and run:

```sh
bbc-sign ledger-sign --address bnb1... --token BNB --amount 12.34567890 --recipient 0xYourBscAddress
```

1. The tool looks for your `bnb1…` address on the device (paths `m/44'/714'/account'/0/index`). Then the
   Ledger shows the address: confirm that it matches.
2. The Ledger shows the claim as three fields, each spread over several pages. **Check the recipient
   carefully.**

| Field on the Ledger | What it is |
|---|---|
| `msgs/amount` | the amount in base units as 64 hex digits (the tool prints the expected value) |
| `msgs/recipient` | your BSC address in lowercase hex. **Compare all 40 characters.** |
| `msgs/token_symbol` | the token symbol in hex, padded with zeros (`424e42…` is "BNB") |

If the address isn't found, check that it's the right Ledger and the right passphrase (if you use one),
then search a wider range with `bbc-sign ledger-find --address bnb1... --max-account 20`.

#### With a recovery phrase or private key (offline computer only)

Build on your normal computer and copy `bbc-sign` (just this one file) to a computer that is **offline**:
network unplugged and Wi-Fi off, ideally booted from a live USB. There, run `bbc-sign selftest`, then
one of:

```sh
bbc-sign mnemonic-sign --address bnb1... --token BNB --amount 12.34567890 --recipient 0xYourBscAddress
bbc-sign key-sign      --address bnb1... --token BNB --amount 12.34567890 --recipient 0xYourBscAddress
```

The phrase (and optional passphrase) or the 64-hex-character private key is read from a hidden prompt.
`mnemonic-sign` searches the standard Beacon Chain paths (`m/44'/714'/account'/0/index`), which wallets
such as Trust Wallet and the Binance Chain wallet used. Bring **only** `signed-recovery.json` back to the
online computer. Afterwards, treat that phrase or key as exposed: move anything else it controls to a new
wallet.

#### What comes out

Either way the result is `signed-recovery.json`. It holds public data only: the claim, your public key and
the signature. It can only ever pay the recipient written inside it. `bbc-sign verify` re-checks it.

### 4. Get the approval (online)

Put `signed-recovery.json` in the recovery folder on the online computer and run:

```sh
bbc-submit approve
```

`approve` does the following:
1. Re-verifies the file: the message, the address derived from your public key, and the signature.
2. Checks with the official API that the token and amount match and that the status is still Pending.
3. Sends the signature to the official API (`/approve`) and saves the raw response.
4. Builds the `recover()` payload and **simulates** it on BSC.

The payload is saved as `recover-payload.json` only after the simulation passes. If you run `approve` again,
it reuses the saved payload instead of asking the API again (`--refresh` asks again).

### 5. Send the claim

On the Ledger, open the **Ethereum** app and turn on *Settings → Blind signing*. Then run:

```sh
bbc-submit send            # add --ledger-live N, --legacy N or --path "m/44'/60'/..." if your recipient isn't Ledger Live account 0
```

`send` refuses if any of these is true:
- the claim is already recovered;
- a transaction from the recipient is still pending;
- the Ledger key isn't the recipient;
- the simulation fails;
- the gas price is above 1 gwei (`--gas-price-gwei` overrides this).

It shows a summary and asks you to type `SEND`. On the Ledger, check:
- the blind-signing warning;
- **To** `0x0000000000000000000000000000000000003000` (TokenRecoverPortal);
- **Amount** 0;
- the network is BNB Smart Chain (chain 56).

The signed transaction is saved to `recover-tx.json` **before** it is broadcast. If no receipt arrives, the
tool reads the chain state and tells you which case you are in:

| What the tool reports | What to do |
|---|---|
| The recovered flag is set | Done. Don't send again. |
| Not accepted or dropped (nonce unused, nothing pending) | Running `send` again is safe: it reuses the same nonce, so at most one transaction can ever be mined. |
| OUTCOME UNKNOWN (pending, or nonce used without a visible receipt) | **Don't send again.** Check the BscScan link and `bbc-submit status` later. |

`bbc-submit rebroadcast` re-sends the exact saved bytes. `bbc-submit bscscan` prints the inputs for sending
`recover()` by hand through BscScan's "Write Contract" page instead.

Turn Blind signing off again when you are done.

### 6. Wait 7 days

```sh
bbc-submit status
```

`status` shows:
- the official API status;
- whether the claim is marked recovered on-chain;
- the locked amount and its `unlockAt` time;
- your saved transactions.

### 7. Withdraw

Once `unlockAt` has passed, run:

```sh
bbc-submit withdraw --dry-run      # all checks and a simulation, no Ledger needed
bbc-submit withdraw                # Ledger Ethereum app, blind signing ON; type WITHDRAW
```

`withdraw` calls `TokenHub.withdrawUnlockedToken(token, recipient)` on `0x…1004`. The contract lets anyone
call this after the lock ends, and it pays **only** the recipient. BNB Chain runs a bot that makes the
same call, roughly 23 days after the lock ends. This step just saves you that wait. A second withdrawal
can't pay twice: it fails with "no locked amount" and costs only gas. Incoming BNB appears in BscScan under
the address's *Internal Transactions* tab.

## Files in a recovery folder

| File | Written by | Contents |
|---|---|---|
| `signed-recovery.json` | `bbc-sign` | Claim parameters, message, public key, signature (public data) |
| `approve-response.json` | `approve` | Raw response of the official approval API |
| `recover-payload.json` | `approve` | `recover()` parameters that passed simulation |
| `recover-tx.json` | `send` | Signed `recover()` transaction and hash, saved before broadcast |
| `withdraw-tx.json` | `withdraw` | Signed withdrawal transaction and hash, saved before broadcast |

Keep these files until the funds have arrived. They contain no secrets. Still, don't publish them: they
link your old and new addresses.

## Troubleshooting

| Problem | Fix |
|---|---|
| Ledger `0x5515` / `0x6982` | The Ledger is locked. Unlock it and open the right app. |
| Ledger `0x6E00` / `0x6D00`, or "wrong app open" | Open the **Binance Chain** app for `bbc-sign`, and the **Ethereum** app for `send`, `withdraw` and `eth-addresses`. |
| Ethereum app `0x6a80` / "Blind signing must be enabled" | In the Ethereum app, turn on *Settings → Blind signing*. |
| "no Ledger found" | Close Ledger Live and any other wallet app using the device. On Linux, install Ledger's udev rules. |
| `bnb1…` not found on the Ledger | Wrong device or passphrase, or a non-standard account. Try `bbc-sign ledger-find --max-account 20 --max-index 50`. |
| "Bad address checksum" | Copy the BSC address in mixed case exactly as your wallet or BscScan shows it. |
| "the API lists X, but the signed file claims Y" | Sign again with the exact symbol and full amount from `bbc-submit lookup`. |
| Status is not Pending | The claim may already have been made: run `bbc-submit status`. NotBounded tokens can't be recovered. |
| "not bound to a BSC token contract" | That BEP2 token has no BSC counterpart, so the contract would lock nothing. The tool refuses on purpose. |
| `send` says the Ledger path is a different address | Pick the path that holds the recipient: `bbc-submit eth-addresses`, then `--ledger-live N` / `--legacy N` / `--path`. |

## How it works

**The claim.** The Beacon Chain key signs this exact JSON message (secp256k1 ECDSA over SHA-256):

```json
{"account_number":"0","chain_id":"Binance-Chain-Tigris","data":null,"memo":"","msgs":[{"amount":"<uint256 hex>","recipient":"<0x… lowercase>","token_symbol":"<bytes32 hex>"}],"sequence":"0","source":"0"}
```

[`core/src/lib.rs`](core/src/lib.rs) builds it. The tests check it byte for byte against:
- the official tool's README example;
- an independent re-implementation of the contract's own template (`_tmSignatureHash`).

**On BSC.** `TokenRecoverPortal` (`0x…3000`) rebuilds that message with `msg.sender` as the recipient, which
is why the claim must be sent from the recipient address. It then checks three things:
1. the owner signature, through the BSC precompile at `0x69`, which accepts low-S signatures only and returns
   the owner's address derived from the public key;
2. BNB Chain's approval signature;
3. the Merkle proof of `keccak256(owner address ‖ symbol ‖ amount)` against the snapshot root.

It then marks the claim as recovered. `TokenHub` (`0x…1004`) locks the funds for the recipient for 7 days
(`LOCK_PERIOD_FOR_TOKEN_RECOVER`). After that, `withdrawUnlockedToken` pays them out.

**Endpoints.** Only `bbc-submit` talks to the network, and only to official BNB Chain endpoints:
- `https://mainnet-token-recover-api.bnbchain.org`: the official recovery API (lookup, status, approval);
- `https://bsc-dataseed.bnbchain.org`: the official BSC RPC.

**Safety properties**

- `bbc-sign` contains no network code, and its only output is public data.
- Each signed file is re-verified on the online side before use. The payload and saved transactions must
  match it.
- Transactions are saved before broadcast. A retry reuses the same nonce. The tool never signs a
  second transaction while an earlier one is unresolved, and every RPC call has a timeout.
- The tool refuses to claim a BEP2 token that has no BSC contract, because the contract would mark that
  claim as used without locking anything.

**References**
- BNB Chain's recovery tool: [`bnb-chain/token-recover-self-service-tools`](https://github.com/bnb-chain/token-recover-self-service-tools)
- Contracts (`TokenRecoverPortal.sol`, `TokenHub.sol`): [`bnb-chain/bsc-genesis-contract`](https://github.com/bnb-chain/bsc-genesis-contract)
- Ledger app protocol: [`LedgerHQ/app-binance`](https://github.com/LedgerHQ/app-binance)

## Status

- **Used on mainnet:** a single-purpose version of this tool, with the claim parameters hardcoded, was used on
  BNB Chain mainnet in November 2026 to recover native BNB with a Ledger (Binance Chain app 2.1.1 plus the
  Ethereum app). That run covered `ledger-sign`, `approve`, `send` and the early `withdraw`. Before
  `recover()` was sent, that version went through two rounds of independent review by three AI models.
- **This repository** is the generic version: the parameters come from the command line and are carried in
  `signed-recovery.json`. Its signing, approval and transaction logic is unchanged. It was checked in three
  ways:
  - the unit tests;
  - read-only runs against the live API and chain, including re-verifying the signed file from that
    mainnet recovery;
  - the official README's example claim (a BEP2 token).

  It has not had a separate independent review.
- **Tested only with public test vectors and read-only checks:** the BEP2-token path (same contracts,
  different token address), `mnemonic-sign` and `key-sign`. These have not been used with real funds.

Issues and pull requests are welcome. Never include a recovery phrase or private key in an issue.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at
your option. The software is provided "as is", without warranty of any kind.
