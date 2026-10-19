# virtual-fido

A software FIDO2 / U2F security key for Linux. It creates a real USB HID authenticator
through `/dev/uhid`, so browsers (WebAuthn), libfido2, `ssh-keygen -t ecdsa-sk` and
anything else that talks to hardware keys will see it as a plugged-in key.

Supported: CTAPHID transport (keepalive, cancel, multiple channels), CTAP2 `getInfo`,
`makeCredential`, `getAssertion`, `getNextAssertion`, `reset`, resident (discoverable)
keys, ES256 with packed self-attestation, and the CTAP1/U2F `REGISTER` /
`AUTHENTICATE` / `VERSION` commands. Not supported yet: PIN / user verification,
extensions (`hmac-secret`, `credProtect`, …), credential management.

> **Security note.** This is a *software* key: private keys live in a file (or in
> memory) on this machine, not in tamper-resistant hardware. Anyone who gets the
> store file and its passphrase gets your credentials. Use it for development,
> testing, or where that trade-off is acceptable.

## Build

```sh
cargo build --release            # add --no-default-features to drop desktop notifications
```

## Run

`/dev/uhid` is root-only by default. Either run with `sudo`, or install the udev rule
in `udev/70-virtual-fido.rules` (instructions inside) to grant a `fido` group access.
The HID node the key creates is made accessible to your desktop session automatically
by systemd's `60-fido-id.rules`, which recognises the FIDO usage page.

```sh
# Persistent, passphrase-encrypted store; approve each request in the terminal.
./target/release/virtual-fido

# Throwaway key that approves everything (testing only).
sudo ./target/release/virtual-fido --store memory --presence auto
```

Options:

| flag | default | |
|---|---|---|
| `--store memory\|file` | `file` | credential store backend |
| `--store-path PATH` | `$XDG_DATA_HOME/virtual-fido/store.bin` | encrypted store file |
| `--passphrase-file PATH` | | else `$VFIDO_PASSPHRASE`, else prompt |
| `--presence auto\|terminal\|notify` | `terminal` | how "touch the key" is confirmed |
| `--presence-timeout SECS` | `30` | |
| `--aaguid HEX` | built-in | 32 hex digits |
| `-v`, `-vv` | | debug / trace logging (`RUST_LOG` also works) |

`notify` shows a desktop notification with Approve / Deny buttons. It needs your D-Bus
session, so run as your own user (via the udev rule), not via `sudo`. Under `sudo` the
default store path is root's home directory; pass `--store-path` if you want your own.

The file store is AES-256-GCM encrypted with a key derived by Argon2id (64 MiB, t=3)
from your passphrase, and is rewritten atomically (mode 0600) on every change,
including signature-counter updates.

## Try it

```sh
python3 scripts/smoke_test.py          # needs python-fido2 0.9.x
fido2-token -L                         # dnf install fido2-tools
ssh-keygen -t ecdsa-sk -O resident     # then: ssh-keygen -K
```

or register and sign in at <https://webauthn.io>.

## Plugins

Storage and user presence are traits, picked by name at startup.

- **Storage**: implement `store::CredentialStore` (`put`, `get`, `list_by_rp`,
  `increment_counter`, `reset`, `attestation`, `set_attestation`) and add a match arm in
  `store::open`. `MemoryStore` (`src/store/memory.rs`) is the simplest example.
- **Presence**: implement `presence::PresenceProvider::request`, which blocks until the
  user answers and should poll the `CancelToken` every ~100 ms; add a match arm in
  `presence::from_name`. See `src/presence/terminal.rs`.

Both are also usable directly from the library: build an `Authenticator` with any
`Box<dyn CredentialStore>` and `Arc<dyn PresenceProvider>`, as the integration tests in
`tests/end_to_end.rs` do.

## Layout

```
src/uhid.rs           /dev/uhid device and report I/O
src/ctaphid.rs        CTAPHID framing, channels, keepalive/cancel, worker threads
src/authenticator.rs  shared state; routes CBOR to ctap2/, APDUs to u2f.rs
src/ctap2/            CTAP2 commands
src/u2f.rs            CTAP1 / U2F
src/store/            CredentialStore trait + memory and encrypted-file backends
src/presence/         PresenceProvider trait + auto, terminal, notify backends
```

## Tests

```sh
cargo test       # drives the whole stack through a fake HID transport
```
