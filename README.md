# virtual-fido

A software FIDO2 / U2F security key for Linux. It creates a real USB HID authenticator
through `/dev/uhid`, so browsers (WebAuthn), libfido2, `ssh-keygen -t ecdsa-sk` and
anything else that talks to hardware keys will see it as a plugged-in key.

Supported:

- CTAPHID transport (keepalive, cancel, multiple channels)
- CTAP2 `getInfo`, `makeCredential`, `getAssertion`, `getNextAssertion`, `reset`,
  `clientPIN` (PIN/UV auth protocols 1 and 2), `credentialManagement`, `largeBlobs`
- extensions: `hmac-secret`, `credProtect`, `largeBlobKey`, `credBlob`
- resident (discoverable) keys; ES256 and Ed25519 credentials with packed
  self-attestation
- CTAP1/U2F `REGISTER` / `AUTHENTICATE` / `VERSION` (ES256 credentials only)

Not supported yet: other extensions (`minPinLength`, …), CTAP 2.1 permission-scoped
PIN tokens, `authenticatorConfig`.

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

## PIN

Set, change and use a PIN with any FIDO2 client, for example `fido2-token -S /dev/hidrawN`
(set), `fido2-token -C /dev/hidrawN` (change), or your browser's security-key settings.
Once a PIN is set:

- creating a credential requires it (the key answers `PIN_REQUIRED` until the client
  sends a PIN-derived token), and the credential is marked user-verified;
- signing in works with or without it; with it, the assertion is marked user-verified;
- 8 wrong guesses in total block the PIN until the key is reset (which deletes all
  credentials); after 3 wrong guesses in a row, restart virtual-fido to try again.

Only a truncated SHA-256 of the PIN is stored, along with the retry counter, in the
credential store. With `--store memory` the PIN disappears on exit like everything else.

## hmac-secret

Credentials created with the `hmac-secret` extension get two random 32-byte secrets,
stored with the credential: one used when the request was PIN-verified, one when not.
A client sends one or two 32-byte salts and gets back HMAC-SHA-256(secret, salt) for
each. The outputs are stable for a given credential and salt, so they can serve as
keys, for example with `systemd-cryptenroll --fido2-device=auto` for disk unlocking or
the WebAuthn PRF extension in browsers. Back up the store file if you depend on them:
losing the credential means losing the derived key.

## credProtect

A client can give a credential a protection level when creating it:

| level | without the PIN | with the PIN |
|---|---|---|
| 1 (default) | usable | usable |
| 2 | usable only if the client names the credential ID; not discoverable | usable |
| 3 | invisible, even by ID (and to U2F) | usable |

Hidden credentials also don't trigger the exclude list, so a site can't use it to
probe for them. A level 3 credential needs a PIN to be set before it can ever be used.
OpenSSH asks for level 3 with `ssh-keygen -t ecdsa-sk -O verify-required`. Chrome
asks for level 2 on discoverable credentials by default, so passkeys it creates only
show up in username-less sign-in after you enter the PIN.

## Credential management

List, rename and delete resident credentials with any client that supports CTAP
credential management, for example:

```sh
fido2-token -I -c /dev/hidrawN          # resident credential count
fido2-token -L -r /dev/hidrawN          # list relying parties
fido2-token -L -k example.com /dev/hidrawN
fido2-token -D -i CREDENTIAL_ID /dev/hidrawN
```

or Chrome's *Settings → Privacy and security → Security → Manage security keys →
Sign-in data*. All of these need the PIN. Up to 1000 resident credentials can be
stored; beyond that, new ones are refused with `KEY_STORE_FULL` (re-registering an
existing user replaces their credential and still works).

Both the CTAP 2.1 command (`0x0A`) and the earlier `FIDO_2_1_PRE` prototype (`0x41`)
are accepted. Requests are authorized with an ordinary PIN token, as on pre-2.1 keys,
because CTAP 2.1 permission-scoped tokens aren't implemented: any client holding a
current PIN token could also manage credentials.

## Large blobs

The key keeps a small array (up to 4096 bytes serialized) on behalf of clients, which
use it for per-credential data, such as the WebAuthn `largeBlob`
extension. Each resident credential created with the `largeBlobKey` extension gets a
32-byte key, returned at creation and on sign-in; clients encrypt their own entries
with it, and the key never looks inside them. Anyone can read the array; once a PIN
is set, writing it needs the PIN. Reset empties it.

## credBlob

A site can store up to 32 bytes with a credential when creating it, and gets them
back in the sign-in response when it asks. Longer blobs aren't stored (the creation
response says so) but the credential is still created. Unlike large-blob entries,
they come back in plain text in the signed sign-in data, so treat them as
configuration, not secrets.

## Try it

```sh
python3 scripts/smoke_test.py          # needs python-fido2 0.9.x
fido2-token -L                         # dnf install fido2-tools
ssh-keygen -t ecdsa-sk -O resident     # then: ssh-keygen -K
ssh-keygen -t ed25519-sk               # Ed25519 works too
```

or register and sign in at <https://webauthn.io>.

## Plugins

Storage and user presence are traits, picked by name at startup.

- **Storage**: implement `store::CredentialStore` (`put`, `get`, `list_by_rp`,
  `list_all`, `delete`, `increment_counter`, `reset`, `attestation`, `set_attestation`,
  `pin`, `set_pin`, `large_blob`, `set_large_blob`) and
  add a match arm in `store::open`. `set_pin` must be durable before it returns, since
  the PIN retry counter relies on it. `MemoryStore` (`src/store/memory.rs`) is the simplest example.
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
src/ctap2/            CTAP2 commands, clientPIN and PIN/UV auth protocols
src/u2f.rs            CTAP1 / U2F
src/store/            CredentialStore trait + memory and encrypted-file backends
src/presence/         PresenceProvider trait + auto, terminal, notify backends
```

## Tests

```sh
cargo test       # drives the whole stack through a fake HID transport

# Interop with python-fido2's independent CTAP2 / PIN implementation, no root needed:
cargo build --example stdio_device && python3 scripts/interop_test.py
```
