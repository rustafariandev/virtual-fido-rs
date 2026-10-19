//! Tests through a real kernel HID device, driven by the independent `ctap-hid-fido2`
//! client library (hidapi over /dev/hidrawN).
//!
//! Each test creates its own uniquely named /dev/uhid device backed by an in-memory
//! authenticator. Creating uhid devices needs root, so every test skips itself unless
//! run as root. `scripts/run-root-tests.sh` builds them as you and runs them with sudo.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ctap_hid_fido2::fidokey::credential_management::credential_management_params::CredentialProtectionPolicy;
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Assertion;
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::Attestation;
use ctap_hid_fido2::fidokey::{
    AssertionExtension as Gext, CredentialExtension as Mext, CredentialSupportedKeyType, GetAssertionArgsBuilder,
    MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier::AttestationVerifyResult;
use ctap_hid_fido2::{verifier, Cfg, FidoKeyHid, HidParam};

use virtual_fido::authenticator::DEFAULT_AAGUID;
use virtual_fido::ctaphid::Server;
use virtual_fido::presence::{AutoPresence, CancelToken, Presence, PresenceProvider, PresenceRequest};
use virtual_fido::store::MemoryStore;
use virtual_fido::uhid::{DeviceInfo, Event, UhidDevice};
use virtual_fido::Authenticator;

const PIN: &str = "1234";

/// Whether the effective user is root, from /proc/self/status ("Uid: real effective ...").
fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            let line = s.lines().find(|l| l.starts_with("Uid:"))?;
            line.split_whitespace().nth(2).map(|euid| euid == "0")
        })
        .unwrap_or(false)
}

/// Starts a virtual key and returns a ctap-hid-fido2 handle to it, or skips the test
/// (returns from it) when not running as root.
macro_rules! virtual_key {
    ($presence:expr) => {
        match VirtualKey::start($presence) {
            Some(key) => key,
            None => {
                eprintln!("skipping: creating a /dev/uhid device needs root (see scripts/run-root-tests.sh)");
                return;
            }
        }
    };
    () => {
        virtual_key!(Arc::new(AutoPresence))
    };
}

struct VirtualKey {
    fido: FidoKeyHid,
}

impl VirtualKey {
    fn start(presence: Arc<dyn PresenceProvider>) -> Option<Self> {
        if !is_root() {
            return None;
        }
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        // A unique name, so parallel tests (and a running virtual-fido) don't collide.
        let name = format!("virtual-fido test {}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst));
        let mut device = UhidDevice::create(&DeviceInfo { name: name.clone(), ..Default::default() })
            .expect("create /dev/uhid device");
        let auth = Authenticator::new(Box::new(MemoryStore::default()), presence, DEFAULT_AAGUID);
        let mut server = Server::new(Arc::new(device.writer().expect("uhid writer")), auth);

        // The device lives until the test process exits; the kernel removes it then.
        std::thread::spawn(move || loop {
            match device.read_event() {
                Ok(Event::Output(report)) => server.handle_report(&report),
                Ok(ev @ (Event::GetReport { .. } | Event::SetReport { .. })) => {
                    let _ = device.reject_report_request(&ev);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        });

        let path = wait_for_hidraw(&name);
        let mut cfg = Cfg::init();
        cfg.enable_keep_alive_msg = false; // no "touch the sensor" lines in test output
        let fido =
            FidoKeyHid::new(&[HidParam::Path(path.clone())], &cfg).unwrap_or_else(|e| panic!("open {path}: {e}"));
        Some(VirtualKey { fido })
    }
}

/// Finds the /dev/hidrawN node of the HID device called `name` via sysfs.
fn wait_for_hidraw(name: &str) -> String {
    for _ in 0..100 {
        if let Ok(entries) = std::fs::read_dir("/sys/class/hidraw") {
            for entry in entries.flatten() {
                let uevent = std::fs::read_to_string(entry.path().join("device/uevent")).unwrap_or_default();
                let node = format!("/dev/{}", entry.file_name().to_string_lossy());
                if uevent.lines().any(|l| l == format!("HID_NAME={name}")) && std::path::Path::new(&node).exists() {
                    return node;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("hidraw node for {name:?} did not appear");
}

/// Checks virtual-fido's packed *self*-attestation. ctap-hid-fido2's
/// `verifier::verify_attestation` only handles attestation with an x5c certificate (it
/// indexes `x5c[0]` and panics without one). A self-attestation signature, made with the
/// credential key, covers the same `authData || SHA-256(challenge)` as an assertion
/// signature, so the library's `verify_assertion` can check it.
fn verify_self_attestation(rpid: &str, challenge: &[u8], attestation: &Attestation) -> AttestationVerifyResult {
    assert_eq!(attestation.fmt, "packed");
    assert!(attestation.attstmt_x5c.is_empty(), "expected self-attestation");
    let as_assertion = Assertion {
        rpid_hash: attestation.rpid_hash.clone(),
        auth_data: attestation.auth_data.clone(),
        signature: attestation.attstmt_sig.clone(),
        ..Default::default()
    };
    AttestationVerifyResult {
        is_success: verifier::verify_assertion(rpid, &attestation.credential_publickey, challenge, &as_assertion),
        credential_id: attestation.credential_descriptor.id.clone(),
        credential_public_key: attestation.credential_publickey.clone(),
    }
}

fn user(id: &[u8], name: &str) -> PublicKeyCredentialUserEntity {
    PublicKeyCredentialUserEntity::new(Some(id), Some(name), Some(name))
}

#[test]
fn get_info() {
    let key = virtual_key!();
    let info = key.fido.get_info().unwrap();
    for v in ["U2F_V2", "FIDO_2_0", "FIDO_2_1"] {
        assert!(info.versions.iter().any(|x| x == v), "{v} in {:?}", info.versions);
    }
    for e in ["credBlob", "credProtect", "hmac-secret", "largeBlobKey", "minPinLength"] {
        assert!(info.extensions.iter().any(|x| x == e), "{e} in {:?}", info.extensions);
    }
    assert_eq!(info.aaguid, DEFAULT_AAGUID);
    assert_eq!(info.pin_uv_auth_protocols, [2, 1]);
    assert_eq!(info.max_cred_blob_length, 32);
    assert_eq!(key.fido.enable_info_option(&InfoOption::Rk).unwrap(), Some(true));
    assert_eq!(key.fido.enable_info_option(&InfoOption::ClientPin).unwrap(), Some(false));
}

#[test]
fn register_and_authenticate_without_pin() {
    let key = virtual_key!();
    let rpid = "no-pin.example";
    for key_type in [CredentialSupportedKeyType::Ecdsa256, CredentialSupportedKeyType::Ed25519] {
        let challenge = verifier::create_challenge();
        let args = MakeCredentialArgsBuilder::new(rpid, &challenge).without_pin_and_uv().key_type(key_type).build();
        let attestation = key.fido.make_credential_with_args(&args).unwrap();
        assert!(attestation.flags.user_present_result);
        assert!(!attestation.flags.user_verified_result);
        let registered = verify_self_attestation(rpid, &challenge, &attestation);
        assert!(registered.is_success, "attestation ({key_type:?})");

        for expected_count in [1, 2] {
            let challenge = verifier::create_challenge();
            let args = GetAssertionArgsBuilder::new(rpid, &challenge)
                .without_pin_and_uv()
                .credential_id(&registered.credential_id)
                .build();
            let assertions = key.fido.get_assertion_with_args(&args).unwrap();
            assert!(verifier::verify_assertion(rpid, &registered.credential_public_key, &challenge, &assertions[0]));
            assert_eq!(assertions[0].sign_count, expected_count);
        }
    }
}

#[test]
fn pin_and_resident_keys() {
    let key = virtual_key!();
    let rpid = "pin.example";
    key.fido.set_new_pin(PIN).unwrap();
    assert_eq!(key.fido.enable_info_option(&InfoOption::ClientPin).unwrap(), Some(true));
    assert_eq!(key.fido.get_pin_retries().unwrap(), 8);

    for (id, name) in [(b"alice".as_slice(), "alice"), (b"bob".as_slice(), "bob")] {
        let challenge = verifier::create_challenge();
        let args = MakeCredentialArgsBuilder::new(rpid, &challenge)
            .pin(PIN)
            .user_entity(&user(id, name))
            .resident_key()
            .build();
        let attestation = key.fido.make_credential_with_args(&args).unwrap();
        assert!(attestation.flags.user_verified_result);
        assert!(verify_self_attestation(rpid, &challenge, &attestation).is_success);
    }

    // Discoverable sign-in returns both accounts (via getNextAssertion).
    let challenge = verifier::create_challenge();
    let assertions = key.fido.get_assertions_rk(rpid, &challenge, Some(PIN)).unwrap();
    let mut names: Vec<_> = assertions.iter().map(|a| a.user.name.clone()).collect();
    names.sort();
    assert_eq!(names, ["alice", "bob"]);
    assert!(assertions.iter().all(|a| a.flags.user_verified_result));

    assert!(key.fido.get_pin_token("0000").is_err(), "wrong PIN");
    assert_eq!(key.fido.get_pin_retries().unwrap(), 7);
    key.fido.change_pin(PIN, "56789").unwrap();
    assert_eq!(key.fido.get_pin_retries().unwrap(), 8);
    assert!(key.fido.get_pin_token(PIN).is_err(), "old PIN");
    assert!(key.fido.get_pin_token("56789").is_ok());
}

#[test]
fn pin_protocol_two() {
    let key = virtual_key!();
    let mut fido = key.fido;
    assert!(fido.set_pin_uv_auth_protocol_two().unwrap());
    fido.set_new_pin(PIN).unwrap();
    let rpid = "v2.example";
    let challenge = verifier::create_challenge();
    let args = MakeCredentialArgsBuilder::new(rpid, &challenge).pin(PIN).build();
    let attestation = fido.make_credential_with_args(&args).unwrap();
    let registered = verify_self_attestation(rpid, &challenge, &attestation);
    assert!(registered.is_success);
    let challenge = verifier::create_challenge();
    let args = GetAssertionArgsBuilder::new(rpid, &challenge).pin(PIN).credential_id(&registered.credential_id).build();
    let assertions = fido.get_assertion_with_args(&args).unwrap();
    assert!(assertions[0].flags.user_verified_result);
    assert!(verifier::verify_assertion(rpid, &registered.credential_public_key, &challenge, &assertions[0]));
}

#[test]
fn extensions() {
    let key = virtual_key!();
    let rpid = "ext.example";
    key.fido.set_new_pin(PIN).unwrap();

    let challenge = verifier::create_challenge();
    let args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(PIN)
        .user_entity(&user(b"ext", "ext"))
        .resident_key()
        .extensions(&[
            Mext::HmacSecret(Some(true)),
            Mext::CredBlob((Some(b"blob!".to_vec()), None)),
            Mext::CredProtect(Some(CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList)),
        ])
        .build();
    let attestation = key.fido.make_credential_with_args(&args).unwrap();
    let registered = verify_self_attestation(rpid, &challenge, &attestation);
    assert!(registered.is_success);
    assert!(
        attestation.extensions.iter().any(|e| matches!(e, Mext::HmacSecret(Some(true)))),
        "{:?}",
        attestation.extensions
    );

    // hmac-secret outputs are stable for a salt; credBlob comes back as stored.
    let get = |salt: &str| {
        let challenge = verifier::create_challenge();
        let args = GetAssertionArgsBuilder::new(rpid, &challenge)
            .pin(PIN)
            .credential_id(&registered.credential_id)
            .extensions(&[Gext::create_hmac_secret_from_string(salt), Gext::CredBlob((Some(true), None))])
            .build();
        let assertion = key.fido.get_assertion_with_args(&args).unwrap().remove(0);
        let hmac = assertion.extensions.iter().find_map(|e| match e {
            Gext::HmacSecret(Some(out)) => Some(*out),
            _ => None,
        });
        let blob = assertion.extensions.iter().find_map(|e| match e {
            Gext::CredBlob((_, Some(b))) => Some(b.clone()),
            _ => None,
        });
        (hmac.expect("hmac-secret output"), blob.expect("credBlob output"))
    };
    let (out1, blob) = get("salt one");
    assert_eq!(blob, b"blob!");
    assert_eq!(get("salt one").0, out1);
    assert_ne!(get("salt two").0, out1);

    // credProtect level 2: hidden from discovery without the PIN.
    let challenge = verifier::create_challenge();
    let args = GetAssertionArgsBuilder::new(rpid, &challenge).without_pin_and_uv().build();
    assert!(key.fido.get_assertion_with_args(&args).is_err());
}

#[test]
fn credential_management_prototype() {
    // ctap-hid-fido2's default: the FIDO_2_1_PRE command (0x41) with a getPinToken token.
    let key = virtual_key!();
    assert!(key.fido.use_pre_credential_management);
    credential_management(key);
}

#[test]
fn credential_management_ctap21() {
    // The CTAP 2.1 command (0x0A) with a token carrying the cm permission.
    let mut key = virtual_key!();
    key.fido.use_pre_credential_management = false;
    credential_management(key);
}

fn credential_management(key: VirtualKey) {
    key.fido.set_new_pin(PIN).unwrap();
    for (rpid, id) in [("a.example", b"a1".as_slice()), ("b.example", b"b1"), ("b.example", b"b2")] {
        let challenge = verifier::create_challenge();
        key.fido.make_credential_rk(rpid, &challenge, Some(PIN), &user(id, &String::from_utf8_lossy(id))).unwrap();
    }

    let meta = key.fido.credential_management_get_creds_metadata(Some(PIN)).unwrap();
    assert_eq!(meta.existing_resident_credentials_count, 3);
    let rps = key.fido.credential_management_enumerate_rps(Some(PIN)).unwrap();
    let mut ids: Vec<_> = rps.iter().map(|rp| rp.public_key_credential_rp_entity.id.clone()).collect();
    ids.sort();
    assert_eq!(ids, ["a.example", "b.example"]);

    let b = rps.iter().find(|rp| rp.public_key_credential_rp_entity.id == "b.example").unwrap();
    let creds = key.fido.credential_management_enumerate_credentials(Some(PIN), &b.rpid_hash).unwrap();
    assert_eq!(creds.len(), 2);

    let target = creds.iter().find(|c| c.public_key_credential_user_entity.id == b"b1").unwrap();
    let renamed = PublicKeyCredentialUserEntity::new(Some(b"b1"), Some("renamed"), Some("Renamed User"));
    key.fido
        .credential_management_update_user_information(
            Some(PIN),
            target.public_key_credential_descriptor.clone(),
            renamed,
        )
        .unwrap();
    key.fido
        .credential_management_delete_credential(Some(PIN), target.public_key_credential_descriptor.clone())
        .unwrap();
    let creds = key.fido.credential_management_enumerate_credentials(Some(PIN), &b.rpid_hash).unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].public_key_credential_user_entity.id, b"b2");
}

#[test]
fn authenticator_config_and_selection() {
    let key = virtual_key!();
    key.fido.selection().unwrap();
    key.fido.set_new_pin(PIN).unwrap();

    key.fido.toggle_always_uv(Some(PIN)).unwrap();
    assert_eq!(key.fido.enable_info_option(&InfoOption::AlwaysUv).unwrap(), Some(true));
    assert!(!key.fido.get_info().unwrap().versions.iter().any(|v| v == "U2F_V2"));
    let challenge = verifier::create_challenge();
    let args = MakeCredentialArgsBuilder::new("cfg.example", &challenge).without_pin_and_uv().build();
    assert!(key.fido.make_credential_with_args(&args).is_err(), "alwaysUv needs the PIN");
    key.fido.toggle_always_uv(Some(PIN)).unwrap();
    assert_eq!(key.fido.enable_info_option(&InfoOption::AlwaysUv).unwrap(), Some(false));

    // Raising the minimum past the PIN's length forces a change.
    key.fido.set_min_pin_length(6, Some(PIN)).unwrap();
    let info = key.fido.get_info().unwrap();
    assert_eq!(info.min_pin_length, 6);
    assert!(info.force_pin_change);
    assert!(key.fido.get_pin_token(PIN).is_err());
    assert!(key.fido.change_pin(PIN, "12345").is_err(), "too short");
    key.fido.change_pin(PIN, "123456").unwrap();
    assert!(!key.fido.get_info().unwrap().force_pin_change);
    assert!(key.fido.get_pin_token("123456").is_ok());
}

#[test]
fn large_blobs() {
    let key = virtual_key!();
    let initial = key.fido.get_large_blob().unwrap();
    assert_eq!(initial.large_blob_array, [0x80], "starts as the empty CBOR array");

    // ctap-hid-fido2 appends the truncated hash; the payload is a CBOR array of one bstr.
    let mut array = vec![0x81, 0x45];
    array.extend_from_slice(b"hello");
    key.fido.write_large_blob(None, array.clone()).unwrap();
    assert_eq!(key.fido.get_large_blob().unwrap().large_blob_array, array);

    // Once a PIN is set, writes need it.
    key.fido.set_new_pin(PIN).unwrap();
    assert!(key.fido.write_large_blob(None, vec![0x80]).is_err());
    key.fido.write_large_blob(Some(PIN), vec![0x80]).unwrap();
    assert_eq!(key.fido.get_large_blob().unwrap().large_blob_array, [0x80]);
}

/// Approves after a delay, so the client sees keepalives over real HID first.
struct SlowPresence;
impl PresenceProvider for SlowPresence {
    fn request(&self, _: &PresenceRequest, cancel: &CancelToken) -> Presence {
        for _ in 0..8 {
            if cancel.is_cancelled() {
                return Presence::Cancelled;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Presence::Approved
    }
}

#[test]
fn keepalives_while_waiting_for_touch() {
    let key = virtual_key!(Arc::new(SlowPresence));
    let rpid = "slow.example";
    let challenge = verifier::create_challenge();
    let args = MakeCredentialArgsBuilder::new(rpid, &challenge).without_pin_and_uv().build();
    let attestation = key.fido.make_credential_with_args(&args).unwrap();
    assert!(verify_self_attestation(rpid, &challenge, &attestation).is_success);
}
