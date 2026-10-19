//! Drives the full stack (CTAPHID -> CTAP2/U2F -> store/presence) through an in-process
//! fake HID transport, acting as the client.

use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciborium::Value;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use virtual_fido::authenticator::DEFAULT_AAGUID;
use virtual_fido::ctap2::cbor::{bytes, get, get_text, int, map, text};
use virtual_fido::ctap2::pin_protocol::{parse_cose_key, PinProtocol};
use virtual_fido::ctaphid::{self, ReportSink, Server, BROADCAST_CID, REPORT_SIZE};
use virtual_fido::presence::{AutoPresence, CancelToken, Presence, PresenceProvider, PresenceRequest};
use virtual_fido::store::{FileStore, KdfParams, MemoryStore};
use virtual_fido::Authenticator;

struct ChannelSink(Mutex<Sender<[u8; REPORT_SIZE]>>);

impl ReportSink for ChannelSink {
    fn send_report(&self, report: &[u8; REPORT_SIZE]) -> io::Result<()> {
        let _ = self.0.lock().unwrap().send(*report);
        Ok(())
    }
}

/// Captures packets the client sends so they can be fed to the server.
struct Collect(Mutex<Vec<[u8; REPORT_SIZE]>>);

impl ReportSink for Collect {
    fn send_report(&self, report: &[u8; REPORT_SIZE]) -> io::Result<()> {
        self.0.lock().unwrap().push(*report);
        Ok(())
    }
}

struct Client {
    server: Server,
    rx: Receiver<[u8; REPORT_SIZE]>,
    cid: u32,
    keepalives: Vec<u8>,
}

impl Client {
    fn new(presence: Arc<dyn PresenceProvider>) -> Self {
        Self::with_auth(Authenticator::new(Box::new(MemoryStore::default()), presence, DEFAULT_AAGUID))
    }

    fn with_auth(auth: Authenticator) -> Self {
        let (tx, rx) = mpsc::channel();
        let server = Server::new(Arc::new(ChannelSink(Mutex::new(tx))), auth);
        let mut c = Client { server, rx, cid: BROADCAST_CID, keepalives: Vec::new() };
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let (cmd, resp) = c.transact(ctaphid::CMD_INIT, &nonce);
        assert_eq!(cmd, ctaphid::CMD_INIT);
        assert_eq!(&resp[..8], &nonce);
        c.cid = u32::from_be_bytes(resp[8..12].try_into().unwrap());
        assert_ne!(c.cid, BROADCAST_CID);
        c
    }

    fn send(&mut self, cmd: u8, data: &[u8]) {
        let collect = Collect(Mutex::new(Vec::new()));
        ctaphid::send_message(&collect, self.cid, cmd, data).unwrap();
        for pkt in collect.0.into_inner().unwrap() {
            self.server.handle_report(&pkt);
        }
    }

    /// Reads one complete message, recording and skipping keepalives.
    fn recv(&mut self) -> (u8, Vec<u8>) {
        loop {
            let pkt = self.rx.recv_timeout(Duration::from_secs(5)).expect("response");
            assert!(pkt[4] & 0x80 != 0, "expected init packet");
            if pkt[4] & 0x7F == ctaphid::CMD_KEEPALIVE {
                self.keepalives.push(pkt[7]);
                continue;
            }
            assert_eq!(u32::from_be_bytes(pkt[..4].try_into().unwrap()), self.cid);
            let cmd = pkt[4] & 0x7F;
            let len = u16::from_be_bytes([pkt[5], pkt[6]]) as usize;
            let mut data = pkt[7..7 + len.min(57)].to_vec();
            let mut seq = 0;
            while data.len() < len {
                let pkt = self.rx.recv_timeout(Duration::from_secs(5)).expect("continuation");
                assert_eq!(pkt[4], seq);
                seq += 1;
                let n = (len - data.len()).min(59);
                data.extend_from_slice(&pkt[5..5 + n]);
            }
            return (cmd, data);
        }
    }

    fn transact(&mut self, cmd: u8, data: &[u8]) -> (u8, Vec<u8>) {
        self.send(cmd, data);
        self.recv()
    }

    /// Sends a CTAP2 command; returns (status, decoded response map).
    fn ctap2(&mut self, cmd: u8, params: Option<Value>) -> (u8, Vec<(Value, Value)>) {
        let mut req = vec![cmd];
        if let Some(p) = params {
            ciborium::ser::into_writer(&p, &mut req).unwrap();
        }
        let (hid_cmd, resp) = self.transact(ctaphid::CMD_CBOR, &req);
        assert_eq!(hid_cmd, ctaphid::CMD_CBOR);
        let body = if resp.len() > 1 {
            match ciborium::de::from_reader(&resp[1..]).unwrap() {
                Value::Map(m) => m,
                other => panic!("not a map: {other:?}"),
            }
        } else {
            Vec::new()
        };
        (resp[0], body)
    }

    fn u2f(&mut self, apdu: &[u8]) -> (Vec<u8>, u16) {
        let (cmd, mut resp) = self.transact(ctaphid::CMD_MSG, apdu);
        assert_eq!(cmd, ctaphid::CMD_MSG);
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        resp.truncate(resp.len() - 2);
        (resp, sw)
    }
}

fn sha256(d: &[u8]) -> [u8; 32] {
    Sha256::digest(d).into()
}

fn make_credential_params(rp: &str, user: &[u8], name: &str, rk: bool, exclude: &[&[u8]]) -> Value {
    let mut entries = vec![
        (int(1), bytes(&[0x11; 32])),
        (int(2), map(vec![(text("id"), text(rp)), (text("name"), text(rp))])),
        (int(3), map(vec![(text("id"), bytes(user)), (text("name"), text(name))])),
        (int(4), Value::Array(vec![map(vec![(text("alg"), int(-7)), (text("type"), text("public-key"))])])),
        (int(7), map(vec![(text("rk"), Value::Bool(rk))])),
    ];
    if !exclude.is_empty() {
        let list = exclude.iter().map(|id| map(vec![(text("id"), bytes(id)), (text("type"), text("public-key"))]));
        entries.push((int(5), Value::Array(list.collect())));
    }
    map(entries)
}

fn get_assertion_params(rp: &str, cdh: &[u8; 32], allow: &[&[u8]]) -> Value {
    let mut entries = vec![(int(1), text(rp)), (int(2), bytes(cdh))];
    if !allow.is_empty() {
        let list = allow.iter().map(|id| map(vec![(text("id"), bytes(id)), (text("type"), text("public-key"))]));
        entries.push((int(3), Value::Array(list.collect())));
    }
    map(entries)
}

/// Parsed attested credential from makeCredential authData.
struct NewCredential {
    id: Vec<u8>,
    key: VerifyingKey,
    flags: u8,
}

fn parse_make_credential(rp: &str, resp: &[(Value, Value)]) -> NewCredential {
    assert_eq!(get(resp, 1).unwrap().as_text(), Some("packed"));
    let ad = get(resp, 2).unwrap().as_bytes().unwrap();
    assert_eq!(&ad[..32], &sha256(rp.as_bytes()));
    assert_eq!(ad[32] & 0x41, 0x41, "UP | AT");
    assert_eq!(&ad[37..53], &DEFAULT_AAGUID);
    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let id = ad[55..55 + id_len].to_vec();
    let cose: Value = ciborium::de::from_reader(&ad[55 + id_len..]).unwrap();
    let cose = cose.as_map().unwrap();
    let x = get(cose, -2).unwrap().as_bytes().unwrap();
    let y = get(cose, -3).unwrap().as_bytes().unwrap();
    let key = VerifyingKey::from_sec1_bytes(&[&[4u8][..], x, y].concat()).unwrap();

    // Self attestation verifies with the credential key.
    let att = get(resp, 3).unwrap().as_map().unwrap();
    let sig = Signature::from_der(get_text(att, "sig").unwrap().as_bytes().unwrap()).unwrap();
    key.verify(&[ad, &[0x11u8; 32][..]].concat(), &sig).unwrap();
    NewCredential { id, key, flags: ad[32] }
}

fn verify_assertion(cred_key: &VerifyingKey, resp: &[(Value, Value)], cdh: &[u8; 32]) -> u32 {
    let ad = get(resp, 2).unwrap().as_bytes().unwrap();
    let sig = Signature::from_der(get(resp, 3).unwrap().as_bytes().unwrap()).unwrap();
    cred_key.verify(&[ad, &cdh[..]].concat(), &sig).unwrap();
    u32::from_be_bytes(ad[33..37].try_into().unwrap())
}

#[test]
fn ping_round_trips_multi_packet_messages() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    assert_eq!(c.transact(ctaphid::CMD_PING, &data), (ctaphid::CMD_PING, data));
}

#[test]
fn unknown_channel_is_rejected() {
    let mut c = Client::new(Arc::new(AutoPresence));
    c.cid = 0x1234_5678;
    assert_eq!(c.transact(ctaphid::CMD_PING, b"x"), (ctaphid::CMD_ERROR, vec![ctaphid::ERR_INVALID_CHANNEL]));
}

#[test]
fn get_info_advertises_fido2_and_u2f() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let (status, info) = c.ctap2(0x04, None);
    assert_eq!(status, 0);
    let versions: Vec<_> = get(&info, 1).unwrap().as_array().unwrap().iter().map(|v| v.as_text().unwrap()).collect();
    assert_eq!(versions, ["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE"]);
    assert_eq!(get(&info, 3).unwrap().as_bytes().unwrap(), &DEFAULT_AAGUID);
    let opts = get(&info, 4).unwrap().as_map().unwrap();
    assert_eq!(get_text(opts, "rk").unwrap().as_bool(), Some(true));
}

#[test]
fn register_and_authenticate_with_allow_list() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let (status, resp) = c.ctap2(0x01, Some(make_credential_params("example.com", b"alice", "alice", false, &[])));
    assert_eq!(status, 0);
    let cred = parse_make_credential("example.com", &resp);

    let cdh = [0x22; 32];
    let (status, resp) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[&cred.id])));
    assert_eq!(status, 0);
    assert_eq!(verify_assertion(&cred.key, &resp, &cdh), 1);
    assert!(get(&resp, 4).is_none(), "no user for non-discoverable credentials");
    let (_, resp) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[&cred.id])));
    assert_eq!(verify_assertion(&cred.key, &resp, &cdh), 2, "counter increments");

    // Wrong RP, and non-discoverable credentials are not found without an allow list.
    assert_eq!(c.ctap2(0x02, Some(get_assertion_params("evil.com", &cdh, &[&cred.id]))).0, 0x2E);
    assert_eq!(c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[]))).0, 0x2E);
}

#[test]
fn resident_keys_with_get_next_assertion() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let (_, r1) = c.ctap2(0x01, Some(make_credential_params("example.com", b"u1", "alice", true, &[])));
    let alice = parse_make_credential("example.com", &r1);
    std::thread::sleep(Duration::from_millis(2));
    let (_, r2) = c.ctap2(0x01, Some(make_credential_params("example.com", b"u2", "bob", true, &[])));
    let bob = parse_make_credential("example.com", &r2);

    let cdh = [0x33; 32];
    let (status, first) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[])));
    assert_eq!(status, 0);
    assert_eq!(get(&first, 5).unwrap().as_integer().map(i128::from), Some(2));
    let user = get(&first, 4).unwrap().as_map().unwrap();
    assert_eq!(get_text(user, "name").unwrap().as_text(), Some("bob"), "newest first");
    verify_assertion(&bob.key, &first, &cdh);

    let (status, second) = c.ctap2(0x08, None);
    assert_eq!(status, 0);
    let user = get(&second, 4).unwrap().as_map().unwrap();
    assert_eq!(get_text(user, "id").unwrap().as_bytes().unwrap(), b"u1");
    verify_assertion(&alice.key, &second, &cdh);
    assert_eq!(c.ctap2(0x08, None).0, 0x30, "no more assertions");

    // Re-registering the same user replaces the old resident key.
    c.ctap2(0x01, Some(make_credential_params("example.com", b"u1", "alice2", true, &[])));
    let (_, first) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[])));
    assert_eq!(get(&first, 5).unwrap().as_integer().map(i128::from), Some(2));
}

#[test]
fn exclude_list_and_reset() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let (_, resp) = c.ctap2(0x01, Some(make_credential_params("example.com", b"alice", "alice", true, &[])));
    let cred = parse_make_credential("example.com", &resp);
    let (status, _) = c.ctap2(0x01, Some(make_credential_params("example.com", b"alice", "alice", true, &[&cred.id])));
    assert_eq!(status, 0x19);

    assert_eq!(c.ctap2(0x07, None).0, 0);
    let cdh = [0; 32];
    assert_eq!(c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[&cred.id]))).0, 0x2E);
}

#[test]
fn rejects_unsupported_algorithms_and_uv() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let params = map(vec![
        (int(1), bytes(&[0; 32])),
        (int(2), map(vec![(text("id"), text("example.com"))])),
        (int(3), map(vec![(text("id"), bytes(b"u"))])),
        (int(4), Value::Array(vec![map(vec![(text("alg"), int(-35)), (text("type"), text("public-key"))])])),
    ]);
    assert_eq!(c.ctap2(0x01, Some(params)).0, 0x26, "ES384 is not supported");
    let params = map(vec![(int(1), text("example.com")), (int(2), bytes(&[0; 32])), (int(5), map(vec![(text("uv"), Value::Bool(true))]))]);
    assert_eq!(c.ctap2(0x02, Some(params)).0, 0x2B);
    assert_eq!(c.ctap2(0x42, None).0, 0x01);
}

struct Deny;
impl PresenceProvider for Deny {
    fn request(&self, _: &PresenceRequest, _: &CancelToken) -> Presence {
        Presence::Denied
    }
}

#[test]
fn custom_presence_plugin_can_deny() {
    let mut c = Client::new(Arc::new(Deny));
    let (status, _) = c.ctap2(0x01, Some(make_credential_params("example.com", b"alice", "alice", true, &[])));
    assert_eq!(status, 0x27);
}

/// Blocks until cancelled.
struct WaitForCancel;
impl PresenceProvider for WaitForCancel {
    fn request(&self, _: &PresenceRequest, cancel: &CancelToken) -> Presence {
        while !cancel.is_cancelled() {
            std::thread::sleep(Duration::from_millis(10));
        }
        Presence::Cancelled
    }
}

#[test]
fn keepalives_while_waiting_and_cancel() {
    let mut c = Client::new(Arc::new(WaitForCancel));
    let mut req = vec![0x01];
    ciborium::ser::into_writer(&make_credential_params("example.com", b"a", "a", false, &[]), &mut req).unwrap();
    c.send(ctaphid::CMD_CBOR, &req);
    std::thread::sleep(Duration::from_millis(350));

    // Another channel is told the device is busy.
    let busy_cid = c.cid;
    c.cid = BROADCAST_CID;
    let (_, init) = c.transact(ctaphid::CMD_INIT, &[9; 8]);
    c.cid = u32::from_be_bytes(init[8..12].try_into().unwrap());
    assert_eq!(c.transact(ctaphid::CMD_PING, b"x"), (ctaphid::CMD_ERROR, vec![ctaphid::ERR_CHANNEL_BUSY]));
    c.cid = busy_cid;

    c.send(ctaphid::CMD_CANCEL, &[]);
    let (cmd, resp) = c.recv();
    assert_eq!((cmd, resp), (ctaphid::CMD_CBOR, vec![0x2D]));
    assert!(c.keepalives.len() >= 2, "got {} keepalives", c.keepalives.len());
    assert!(c.keepalives.iter().all(|&s| s == 2), "status UPNEEDED");
}

#[test]
fn u2f_register_and_authenticate() {
    let mut c = Client::new(Arc::new(AutoPresence));
    assert_eq!(c.u2f(&[0, 3, 0, 0, 0]), (b"U2F_V2".to_vec(), 0x9000));

    let challenge = [0xAA; 32];
    let app = sha256(b"https://example.com");
    let mut apdu = vec![0, 1, 3, 0, 64];
    apdu.extend_from_slice(&challenge);
    apdu.extend_from_slice(&app);
    let (resp, sw) = c.u2f(&apdu);
    assert_eq!(sw, 0x9000);
    assert_eq!(resp[0], 0x05);
    let pubkey = &resp[1..66];
    let kh_len = resp[66] as usize;
    let kh = resp[67..67 + kh_len].to_vec();
    let cred_key = VerifyingKey::from_sec1_bytes(pubkey).unwrap();

    let authenticate = |mode: u8, kh: &[u8]| {
        let mut apdu = vec![0, 2, mode, 0, (65 + kh.len()) as u8];
        apdu.extend_from_slice(&challenge);
        apdu.extend_from_slice(&app);
        apdu.push(kh.len() as u8);
        apdu.extend_from_slice(kh);
        apdu
    };
    assert_eq!(c.u2f(&authenticate(0x07, &kh)).1, 0x6985, "check-only: known handle");
    assert_eq!(c.u2f(&authenticate(0x07, &[0; 16])).1, 0x6A80, "check-only: unknown handle");

    let (resp, sw) = c.u2f(&authenticate(0x03, &kh));
    assert_eq!(sw, 0x9000);
    assert_eq!(resp[0], 0x01);
    let counter = &resp[1..5];
    let sig = Signature::from_der(&resp[5..]).unwrap();
    cred_key.verify(&[&app[..], &[0x01], counter, &challenge].concat(), &sig).unwrap();

    // The same credential works over CTAP2 when the RP ID hashes to the app parameter.
    let (status, resp) = c.ctap2(0x02, Some(get_assertion_params("https://example.com", &[0; 32], &[&kh])));
    assert_eq!(status, 0);
    verify_assertion(&cred_key, &resp, &[0; 32]);
}

#[test]
fn file_store_persists_and_checks_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.bin");
    let params = KdfParams { m_cost: 64, t_cost: 1, p_cost: 1 };
    let cdh = [0x44; 32];

    let cred = {
        let store = FileStore::open_with_params(&path, "hunter2", params).unwrap();
        let mut c = Client::with_auth(Authenticator::new(Box::new(store), Arc::new(AutoPresence), DEFAULT_AAGUID));
        let (_, resp) = c.ctap2(0x01, Some(make_credential_params("example.com", b"alice", "alice", true, &[])));
        parse_make_credential("example.com", &resp)
    };

    assert!(FileStore::open(&path, "wrong").is_err());

    let store = FileStore::open(&path, "hunter2").unwrap();
    let mut c = Client::with_auth(Authenticator::new(Box::new(store), Arc::new(AutoPresence), DEFAULT_AAGUID));
    let (status, resp) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[])));
    assert_eq!(status, 0);
    assert_eq!(verify_assertion(&cred.key, &resp, &cdh), 1);

    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}

// ---- client PIN -------------------------------------------------------------------

impl Client {
    /// clientPIN request; `entries` excludes the protocol and subcommand.
    fn client_pin(&mut self, protocol: PinProtocol, sub: i64, mut entries: Vec<(Value, Value)>) -> (u8, Vec<(Value, Value)>) {
        entries.push((int(1), int(protocol.id())));
        entries.push((int(2), int(sub)));
        self.ctap2(0x06, Some(map(entries)))
    }

    /// Runs key agreement; returns our COSE key and the shared secret.
    fn key_agreement(&mut self, protocol: PinProtocol) -> (Value, Vec<u8>) {
        let (status, resp) = self.client_pin(protocol, 2, vec![]);
        assert_eq!(status, 0);
        let peer = parse_cose_key(get(&resp, 1).unwrap()).unwrap();
        let (cose, secret) = protocol.encapsulate(&peer);
        (cose, secret.to_vec())
    }

    fn set_pin(&mut self, protocol: PinProtocol, pin: &str) -> u8 {
        let (cose, secret) = self.key_agreement(protocol);
        let new_pin_enc = protocol.encrypt(&secret, &pad_pin(pin));
        let pin_auth = protocol.authenticate_with_secret(&secret, &new_pin_enc);
        self.client_pin(protocol, 3, vec![(int(3), cose), (int(4), bytes(&pin_auth)), (int(5), bytes(&new_pin_enc))]).0
    }

    fn change_pin(&mut self, protocol: PinProtocol, old: &str, new: &str) -> u8 {
        let (cose, secret) = self.key_agreement(protocol);
        let pin_hash_enc = protocol.encrypt(&secret, &sha256(old.as_bytes())[..16]);
        let new_pin_enc = protocol.encrypt(&secret, &pad_pin(new));
        let pin_auth = protocol.authenticate_with_secret(&secret, &[&new_pin_enc[..], &pin_hash_enc].concat());
        let entries = vec![(int(3), cose), (int(4), bytes(&pin_auth)), (int(5), bytes(&new_pin_enc)), (int(6), bytes(&pin_hash_enc))];
        self.client_pin(protocol, 4, entries).0
    }

    fn pin_token(&mut self, protocol: PinProtocol, pin: &str) -> Result<Vec<u8>, u8> {
        let (cose, secret) = self.key_agreement(protocol);
        let pin_hash_enc = protocol.encrypt(&secret, &sha256(pin.as_bytes())[..16]);
        let (status, resp) = self.client_pin(protocol, 5, vec![(int(3), cose), (int(6), bytes(&pin_hash_enc))]);
        if status != 0 {
            return Err(status);
        }
        let enc = get(&resp, 2).unwrap().as_bytes().unwrap();
        Ok(protocol.decrypt(&secret, enc).unwrap().to_vec())
    }

    fn pin_retries(&mut self) -> i128 {
        let (status, resp) = self.client_pin(PinProtocol::V1, 1, vec![]);
        assert_eq!(status, 0);
        get(&resp, 3).unwrap().as_integer().unwrap().into()
    }

    fn client_pin_option(&mut self) -> bool {
        let (_, info) = self.ctap2(0x04, None);
        get_text(get(&info, 4).unwrap().as_map().unwrap(), "clientPin").unwrap().as_bool().unwrap()
    }
}

fn pad_pin(pin: &str) -> Vec<u8> {
    let mut p = pin.as_bytes().to_vec();
    p.resize(64, 0);
    p
}

fn with_pin_auth(params: Value, key: (i64, i64), protocol: PinProtocol, token: &[u8], cdh: &[u8]) -> Value {
    let Value::Map(mut entries) = params else { unreachable!() };
    entries.push((int(key.0), bytes(&protocol.authenticate(token, cdh))));
    entries.push((int(key.1), int(protocol.id())));
    map(entries)
}

#[test]
fn pin_set_use_and_change() {
    for protocol in PinProtocol::SUPPORTED {
        let mut c = Client::new(Arc::new(AutoPresence));
        assert!(!c.client_pin_option());
        let (_, info) = c.ctap2(0x04, None);
        let protocols: Vec<i128> = get(&info, 6).unwrap().as_array().unwrap().iter().map(|v| v.as_integer().unwrap().into()).collect();
        assert_eq!(protocols, [2, 1]);
        assert_eq!(c.pin_token(protocol, "1234"), Err(0x35), "no PIN yet");

        assert_eq!(c.set_pin(protocol, "123"), 0x37, "too short");
        assert_eq!(c.set_pin(protocol, "1234"), 0);
        assert!(c.client_pin_option());
        assert_eq!(c.set_pin(protocol, "5678"), 0x30, "already set");

        // makeCredential now requires the PIN.
        let params = make_credential_params("example.com", b"alice", "alice", true, &[]);
        assert_eq!(c.ctap2(0x01, Some(params.clone())).0, 0x36);
        let token = c.pin_token(protocol, "1234").unwrap();
        assert_eq!(token.len(), 32);
        let (status, resp) = c.ctap2(0x01, Some(with_pin_auth(params.clone(), (8, 9), protocol, &token, &[0x11; 32])));
        assert_eq!(status, 0);
        let cred = parse_make_credential("example.com", &resp);
        assert_eq!(cred.flags, 0x45, "UP | UV | AT");
        let (status, _) = c.ctap2(0x01, Some(with_pin_auth(params, (8, 9), protocol, &token, &[0x99; 32])));
        assert_eq!(status, 0x33, "pinUvAuthParam over the wrong hash");

        // getAssertion works with or without the PIN; UV reflects which.
        let cdh = [0x55; 32];
        let (status, resp) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[])));
        assert_eq!(status, 0);
        assert_eq!(get(&resp, 2).unwrap().as_bytes().unwrap()[32], 0x01);
        let (status, resp) = c.ctap2(0x02, Some(with_pin_auth(get_assertion_params("example.com", &cdh, &[]), (6, 7), protocol, &token, &cdh)));
        assert_eq!(status, 0);
        assert_eq!(get(&resp, 2).unwrap().as_bytes().unwrap()[32], 0x05);
        verify_assertion(&cred.key, &resp, &cdh);

        assert_eq!(c.change_pin(protocol, "0000", "abcd"), 0x31, "wrong old PIN");
        assert_eq!(c.pin_retries(), 7);
        assert_eq!(c.change_pin(protocol, "1234", "abcd"), 0);
        assert_eq!(c.pin_retries(), 8);
        assert_eq!(c.pin_token(protocol, "1234"), Err(0x31));
        let new_token = c.pin_token(protocol, "abcd").unwrap();
        // Changing the PIN and issuing a new token invalidate the old one.
        let params = get_assertion_params("example.com", &cdh, &[]);
        assert_eq!(c.ctap2(0x02, Some(with_pin_auth(params.clone(), (6, 7), protocol, &token, &cdh))).0, 0x33);
        assert_eq!(c.ctap2(0x02, Some(with_pin_auth(params, (6, 7), protocol, &new_token, &cdh))).0, 0);
    }
}

#[test]
fn pin_retry_limits() {
    let p = PinProtocol::V2;
    let mut c = Client::new(Arc::new(AutoPresence));
    assert_eq!(c.set_pin(p, "1234"), 0);
    assert_eq!(c.pin_token(p, "0000"), Err(0x31));
    assert_eq!(c.pin_token(p, "0000"), Err(0x31));
    assert_eq!(c.pin_token(p, "0000"), Err(0x34), "third consecutive failure needs a power cycle");
    assert_eq!(c.pin_token(p, "1234"), Err(0x34), "even the right PIN");
    assert_eq!(c.pin_retries(), 5);
}

#[test]
fn pin_blocks_after_eight_failures_and_reset_clears_it() {
    let p = PinProtocol::V1;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.bin");
    let params = KdfParams { m_cost: 64, t_cost: 1, p_cost: 1 };
    let new_client = || {
        let store = FileStore::open_with_params(&path, "pw", params).unwrap();
        Client::with_auth(Authenticator::new(Box::new(store), Arc::new(AutoPresence), DEFAULT_AAGUID))
    };

    let mut c = new_client();
    assert_eq!(c.set_pin(p, "1234"), 0);
    drop(c);
    let mut statuses = Vec::new();
    // Each "power cycle" (fresh authenticator on the same store) allows 3 more guesses.
    for _ in 0..3 {
        let mut c = new_client();
        for _ in 0..3 {
            statuses.push(c.pin_token(p, "0000").unwrap_err());
        }
    }
    assert_eq!(statuses, [0x31, 0x31, 0x34, 0x31, 0x31, 0x34, 0x31, 0x32, 0x32]);

    let mut c = new_client();
    assert_eq!(c.pin_retries(), 0, "retries persist across restarts");
    assert_eq!(c.pin_token(p, "1234"), Err(0x32), "blocked");
    assert_eq!(c.ctap2(0x07, None).0, 0);
    assert!(!c.client_pin_option(), "reset removes the PIN");
    assert_eq!(c.set_pin(p, "4321"), 0);
    assert!(c.pin_token(p, "4321").is_ok());
}

// ---- hmac-secret ------------------------------------------------------------------

fn with_extensions(params: Value, key: i64, extensions: Value) -> Value {
    let Value::Map(mut entries) = params else { unreachable!() };
    entries.push((int(key), extensions));
    map(entries)
}

/// Splits authenticatorData into (flags, extensions map if ED is set).
fn auth_data_extensions(ad: &[u8]) -> (u8, Option<Value>) {
    let flags = ad[32];
    let mut rest = &ad[37..];
    if flags & 0x40 != 0 {
        let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        rest = &ad[55 + id_len..];
        let _cose: Value = ciborium::de::from_reader(&mut rest).unwrap();
    }
    if flags & 0x80 == 0 {
        assert!(rest.is_empty());
        return (flags, None);
    }
    let ext: Value = ciborium::de::from_reader(&mut rest).unwrap();
    assert!(rest.is_empty(), "trailing bytes after extensions");
    (flags, Some(ext))
}

impl Client {
    /// getAssertion with an hmac-secret request; returns (status, flags, decrypted outputs).
    fn get_hmac_secret(
        &mut self,
        protocol: PinProtocol,
        salts: &[u8],
        pin_token: Option<&[u8]>,
        tamper: bool,
    ) -> (u8, u8, Option<Vec<u8>>) {
        let (cose, secret) = self.key_agreement(protocol);
        let salt_enc = protocol.encrypt(&secret, salts);
        let mut salt_auth = protocol.authenticate_with_secret(&secret, &salt_enc);
        if tamper {
            salt_auth[0] ^= 1;
        }
        let ext = map(vec![(
            text("hmac-secret"),
            map(vec![(int(1), cose), (int(2), bytes(&salt_enc)), (int(3), bytes(&salt_auth)), (int(4), int(protocol.id()))]),
        )]);
        let cdh = [0x66; 32];
        let mut params = with_extensions(get_assertion_params("example.com", &cdh, &[]), 4, ext);
        if let Some(token) = pin_token {
            params = with_pin_auth(params, (6, 7), protocol, token, &cdh);
        }
        let (status, resp) = self.ctap2(0x02, Some(params));
        if status != 0 {
            return (status, 0, None);
        }
        let (flags, ext) = auth_data_extensions(get(&resp, 2).unwrap().as_bytes().unwrap());
        let out = ext.map(|e| {
            let enc = get_text(e.as_map().unwrap(), "hmac-secret").unwrap().as_bytes().unwrap().clone();
            protocol.decrypt(&secret, &enc).unwrap().to_vec()
        });
        (status, flags, out)
    }
}

fn hmac_secret_credential(c: &mut Client, user: &[u8], pin_token: Option<(PinProtocol, &[u8])>) -> NewCredential {
    let ext = map(vec![(text("hmac-secret"), Value::Bool(true))]);
    let mut params = with_extensions(make_credential_params("example.com", user, "u", true, &[]), 6, ext);
    if let Some((p, token)) = pin_token {
        params = with_pin_auth(params, (8, 9), p, token, &[0x11; 32]);
    }
    let (status, resp) = c.ctap2(0x01, Some(params));
    assert_eq!(status, 0);
    let ad = get(&resp, 2).unwrap().as_bytes().unwrap();
    let (flags, ext) = auth_data_extensions(ad);
    assert_eq!(flags & 0x80, 0x80, "ED");
    assert_eq!(ext, Some(map(vec![(text("hmac-secret"), Value::Bool(true))])));
    parse_make_credential("example.com", &resp)
}

#[test]
fn hmac_secret_outputs() {
    for protocol in PinProtocol::SUPPORTED {
        let mut c = Client::new(Arc::new(AutoPresence));
        let (_, info) = c.ctap2(0x04, None);
        assert_eq!(
            get(&info, 2),
            Some(&Value::Array(vec![text("credBlob"), text("credProtect"), text("hmac-secret"), text("largeBlobKey")]))
        );
        hmac_secret_credential(&mut c, b"u1", None);

        let salt1 = [1u8; 32];
        let salt2 = [2u8; 32];
        let (status, flags, out1) = c.get_hmac_secret(protocol, &salt1, None, false);
        assert_eq!(status, 0);
        assert_eq!(flags, 0x81, "UP | ED");
        let out1 = out1.unwrap();
        assert_eq!(out1.len(), 32);

        // Deterministic per salt, and independent of the (fresh) shared secret.
        assert_eq!(c.get_hmac_secret(protocol, &salt1, None, false).2.unwrap(), out1);
        let both = c.get_hmac_secret(protocol, &[salt1, salt2].concat(), None, false).2.unwrap();
        assert_eq!(both.len(), 64);
        assert_eq!(&both[..32], &out1[..]);
        assert_ne!(&both[32..], &out1[..]);

        // With the PIN the credential's other secret is used.
        assert_eq!(c.set_pin(protocol, "1234"), 0);
        let token = c.pin_token(protocol, "1234").unwrap();
        let (status, flags, out_uv) = c.get_hmac_secret(protocol, &salt1, Some(&token), false);
        assert_eq!((status, flags), (0, 0x85), "UP | UV | ED");
        assert_ne!(out_uv.unwrap(), out1);

        assert_eq!(c.get_hmac_secret(protocol, &salt1, None, true).0, 0x33, "bad saltAuth");
        assert_eq!(c.get_hmac_secret(protocol, &[0u8; 16], None, false).0, 0x03, "bad salt length");
    }
}

#[test]
fn hmac_secret_with_multiple_credentials() {
    let p = PinProtocol::V2;
    let mut c = Client::new(Arc::new(AutoPresence));
    // A credential without the extension gets no output (and no ED flag).
    c.ctap2(0x01, Some(make_credential_params("example.com", b"plain", "p", true, &[])));
    std::thread::sleep(Duration::from_millis(2));
    hmac_secret_credential(&mut c, b"secret", None);

    let (cose, secret) = c.key_agreement(p);
    let salt_enc = p.encrypt(&secret, &[7u8; 32]);
    let salt_auth = p.authenticate_with_secret(&secret, &salt_enc);
    let ext = map(vec![(text("hmac-secret"), map(vec![(int(1), cose), (int(2), bytes(&salt_enc)), (int(3), bytes(&salt_auth)), (int(4), int(2))]))]);
    let (status, first) = c.ctap2(0x02, Some(with_extensions(get_assertion_params("example.com", &[0; 32], &[]), 4, ext)));
    assert_eq!(status, 0);
    let (flags, ext) = auth_data_extensions(get(&first, 2).unwrap().as_bytes().unwrap());
    assert_eq!(flags, 0x81, "newest (hmac-secret) credential first");
    let enc = get_text(ext.unwrap().as_map().unwrap(), "hmac-secret").unwrap().as_bytes().unwrap().clone();
    assert_eq!(p.decrypt(&secret, &enc).unwrap().len(), 32);

    let (status, second) = c.ctap2(0x08, None);
    assert_eq!(status, 0);
    assert_eq!(auth_data_extensions(get(&second, 2).unwrap().as_bytes().unwrap()), (0x01, None));
}

// ---- credProtect ------------------------------------------------------------------

/// Creates a resident credential with credProtect `level` (and optionally hmac-secret).
fn protected_credential(c: &mut Client, user: &[u8], level: i64, hmac: bool, pin: Option<(PinProtocol, &[u8])>) -> (u8, Option<NewCredential>, Option<Value>) {
    let mut ext = vec![(text("credProtect"), int(level))];
    if hmac {
        ext.push((text("hmac-secret"), Value::Bool(true)));
    }
    let mut params = with_extensions(make_credential_params("example.com", user, "u", true, &[]), 6, map(ext));
    if let Some((p, token)) = pin {
        params = with_pin_auth(params, (8, 9), p, token, &[0x11; 32]);
    }
    let (status, resp) = c.ctap2(0x01, Some(params));
    if status != 0 {
        return (status, None, None);
    }
    let (_, ext) = auth_data_extensions(get(&resp, 2).unwrap().as_bytes().unwrap());
    (status, Some(parse_make_credential("example.com", &resp)), ext)
}

#[test]
fn cred_protect_levels() {
    let p = PinProtocol::V2;
    let mut c = Client::new(Arc::new(AutoPresence));
    let (_, cred2, ext) = protected_credential(&mut c, b"two", 2, false, None);
    let cred2 = cred2.unwrap();
    assert_eq!(ext, Some(map(vec![(text("credProtect"), int(2))])), "echoed in authData");
    let (_, cred3, ext) = protected_credential(&mut c, b"three", 3, true, None);
    let cred3 = cred3.unwrap();
    assert_eq!(ext, Some(map(vec![(text("credProtect"), int(3)), (text("hmac-secret"), Value::Bool(true))])));
    let (_, cred1, ext) = protected_credential(&mut c, b"one", 1, false, None);
    let cred1 = cred1.unwrap();
    assert_eq!(ext, Some(map(vec![(text("credProtect"), int(1))])));
    // Unknown levels are ignored: no protection, nothing echoed.
    let (status, _, ext) = protected_credential(&mut c, b"nine", 9, false, None);
    assert_eq!((status, ext), (0, None));

    let cdh = [0x77; 32];
    let assert_with = |c: &mut Client, allow: &[&[u8]], token: Option<&[u8]>| {
        let mut params = get_assertion_params("example.com", &cdh, allow);
        if let Some(t) = token {
            params = with_pin_auth(params, (6, 7), p, t, &cdh);
        }
        c.ctap2(0x02, Some(params))
    };
    let count = |resp: &[(Value, Value)]| get(resp, 5).map_or(1, |n| i128::from(n.as_integer().unwrap()));

    // Without UV: discovery sees levels 1 and the ignored one, not 2 or 3.
    let (status, resp) = assert_with(&mut c, &[], None);
    assert_eq!((status, count(&resp)), (0, 2));
    // Level 2 is fine when named; level 3 is not, even by ID.
    assert_eq!(assert_with(&mut c, &[&cred2.id], None).0, 0);
    assert_eq!(assert_with(&mut c, &[&cred3.id], None).0, 0x2E);
    assert_eq!(assert_with(&mut c, &[&cred1.id], None).0, 0);

    // The exclude list cannot reveal a level 3 credential without UV, so this
    // registration succeeds (and replaces the old credential for user "three").
    let params = make_credential_params("example.com", b"three", "u", true, &[&cred3.id]);
    let (status, resp) = c.ctap2(0x01, Some(params));
    assert_eq!(status, 0);
    let cred3b = parse_make_credential("example.com", &resp);

    // U2F has no UV, so level 3 credentials are unknown to it.
    let app = sha256(b"example.com");
    let (_, cred3c, _) = protected_credential(&mut c, b"three-c", 3, false, None);
    let kh = cred3c.unwrap().id;
    let mut apdu = vec![0, 2, 0x07, 0, (65 + kh.len()) as u8];
    apdu.extend_from_slice(&[0; 32]);
    apdu.extend_from_slice(&app);
    apdu.push(kh.len() as u8);
    apdu.extend_from_slice(&kh);
    assert_eq!(c.u2f(&apdu).1, 0x6A80);
    let kh2 = &cred2.id;
    let mut apdu2 = vec![0, 2, 0x07, 0, (65 + kh2.len()) as u8];
    apdu2.extend_from_slice(&[0; 32]);
    apdu2.extend_from_slice(&app);
    apdu2.push(kh2.len() as u8);
    apdu2.extend_from_slice(kh2);
    assert_eq!(c.u2f(&apdu2).1, 0x6985, "level 2 is known to U2F (key handle is named)");

    // With UV everything is visible.
    assert_eq!(c.set_pin(p, "1234"), 0);
    let token = c.pin_token(p, "1234").unwrap();
    let (status, resp) = assert_with(&mut c, &[], Some(&token));
    assert_eq!((status, count(&resp)), (0, 5));
    let (status, resp) = assert_with(&mut c, &[&cred3b.id], Some(&token));
    assert_eq!(status, 0);
    verify_assertion(&cred3b.key, &resp, &cdh);
    let params = make_credential_params("example.com", b"x", "u", true, &[&cred3b.id]);
    let (status, _) = c.ctap2(0x01, Some(with_pin_auth(params, (8, 9), p, &token, &[0x11; 32])));
    assert_eq!(status, 0x19, "excluded once the user is verified");
}

// ---- credential management --------------------------------------------------------

impl Client {
    /// credentialManagement request (command `cmd`: 0x0A or the 0x41 prototype),
    /// authenticated with `token` unless it is None.
    fn cred_mgmt(&mut self, cmd: u8, sub: i64, params: Option<Value>, token: Option<(PinProtocol, &[u8])>) -> (u8, Vec<(Value, Value)>) {
        let mut entries = vec![(int(1), int(sub))];
        let mut msg = vec![sub as u8];
        if let Some(p) = params {
            ciborium::ser::into_writer(&p, &mut msg).unwrap();
            entries.push((int(2), p));
        }
        if let Some((protocol, token)) = token {
            entries.push((int(3), int(protocol.id())));
            entries.push((int(4), bytes(&protocol.authenticate(token, &msg))));
        }
        self.ctap2(cmd, Some(map(entries)))
    }
}

fn credential_descriptor(id: &[u8]) -> Value {
    map(vec![(text("id"), bytes(id)), (text("type"), text("public-key"))])
}

#[test]
fn credential_management() {
    let p = PinProtocol::V1;
    let mut c = Client::new(Arc::new(AutoPresence));
    let (_, info) = c.ctap2(0x04, None);
    let opts = get(&info, 4).unwrap().as_map().unwrap();
    assert_eq!(get_text(opts, "credMgmt").unwrap().as_bool(), Some(true));

    // Two RPs with resident keys, plus a non-resident credential that is never listed.
    let rp_params = |rp: &str, user: &[u8], name: &str| make_credential_params(rp, user, name, true, &[]);
    let (_, r) = c.ctap2(0x01, Some(rp_params("b.example", b"u1", "alice")));
    let alice = parse_make_credential("b.example", &r);
    std::thread::sleep(Duration::from_millis(2));
    let (_, r) = c.ctap2(0x01, Some(rp_params("b.example", b"u2", "bob")));
    let bob = parse_make_credential("b.example", &r);
    c.ctap2(0x01, Some(rp_params("a.example", b"u3", "carol")));
    c.ctap2(0x01, Some(make_credential_params("a.example", b"u4", "dave", false, &[])));

    // Needs a PIN token.
    assert_eq!(c.cred_mgmt(0x0A, 1, None, None).0, 0x36);
    assert_eq!(c.set_pin(p, "1234"), 0);
    let token = c.pin_token(p, "1234").unwrap();
    let auth = Some((p, token.as_slice()));
    assert_eq!(c.cred_mgmt(0x0A, 1, None, Some((p, &[0u8; 32]))).0, 0x33, "wrong token");

    let (status, meta) = c.cred_mgmt(0x0A, 1, None, auth);
    assert_eq!(status, 0);
    assert_eq!(get(&meta, 1), Some(&int(3)));
    assert_eq!(get(&meta, 2), Some(&int(997)));

    // RPs come back sorted by ID; the prototype command works the same.
    for cmd in [0x0A, 0x41] {
        let (status, first) = c.cred_mgmt(cmd, 2, None, auth);
        assert_eq!(status, 0);
        assert_eq!(get(&first, 5), Some(&int(2)));
        let rp = get(&first, 3).unwrap().as_map().unwrap();
        assert_eq!(get_text(rp, "id"), Some(&text("a.example")));
        assert_eq!(get_text(rp, "name"), Some(&text("a.example")));
        assert_eq!(get(&first, 4).unwrap().as_bytes().unwrap(), &sha256(b"a.example"));
        let (status, second) = c.cred_mgmt(cmd, 3, None, None);
        assert_eq!(status, 0);
        assert_eq!(get_text(get(&second, 3).unwrap().as_map().unwrap(), "id"), Some(&text("b.example")));
        assert_eq!(c.cred_mgmt(cmd, 3, None, None).0, 0x30, "enumeration finished");
    }

    // Credentials for b.example, newest first, with matching public keys.
    let rp_hash = map(vec![(int(1), bytes(&sha256(b"b.example")))]);
    let (status, first) = c.cred_mgmt(0x0A, 4, Some(rp_hash.clone()), auth);
    assert_eq!(status, 0);
    assert_eq!(get(&first, 9), Some(&int(2)));
    assert_eq!(get(&first, 7), Some(&credential_descriptor(&bob.id)));
    let cose = get(&first, 8).unwrap().as_map().unwrap();
    let x = get(cose, -2).unwrap().as_bytes().unwrap();
    assert_eq!(&bob.key.to_encoded_point(false).as_bytes()[1..33], &x[..]);
    assert_eq!(get(&first, 0x0A), Some(&int(1)), "credProtect level");
    let (status, second) = c.cred_mgmt(0x0A, 5, None, None);
    assert_eq!(status, 0);
    assert_eq!(get(&second, 7), Some(&credential_descriptor(&alice.id)));
    let user = get(&second, 6).unwrap().as_map().unwrap();
    assert_eq!(get_text(user, "name"), Some(&text("alice")));
    // Another command in between ends the enumeration.
    c.cred_mgmt(0x0A, 4, Some(rp_hash.clone()), auth);
    c.ctap2(0x04, None);
    assert_eq!(c.cred_mgmt(0x0A, 5, None, None).0, 0x30);

    // Rename alice: the new user entity replaces the old one.
    let update = map(vec![
        (int(2), credential_descriptor(&alice.id)),
        (int(3), map(vec![(text("id"), bytes(b"u1")), (text("displayName"), text("Alice A."))])),
    ]);
    assert_eq!(c.cred_mgmt(0x0A, 7, Some(update), auth).0, 0);
    let wrong_user = map(vec![(int(2), credential_descriptor(&alice.id)), (int(3), map(vec![(text("id"), bytes(b"zz"))]))]);
    assert_eq!(c.cred_mgmt(0x0A, 7, Some(wrong_user), auth).0, 0x02);

    // Delete bob; alice remains with her new name.
    let delete = map(vec![(int(2), credential_descriptor(&bob.id))]);
    assert_eq!(c.cred_mgmt(0x0A, 6, Some(delete.clone()), auth).0, 0);
    assert_eq!(c.cred_mgmt(0x0A, 6, Some(delete), auth).0, 0x2E, "already gone");
    let (status, only) = c.cred_mgmt(0x0A, 4, Some(rp_hash), auth);
    assert_eq!(status, 0);
    assert_eq!(get(&only, 9), Some(&int(1)));
    let user = get(&only, 6).unwrap().as_map().unwrap();
    assert_eq!(get_text(user, "displayName"), Some(&text("Alice A.")));
    assert_eq!(get_text(user, "name"), None);
    let cdh = [0; 32];
    assert_eq!(c.ctap2(0x02, Some(get_assertion_params("b.example", &cdh, &[&bob.id]))).0, 0x2E);

    let no_rp = map(vec![(int(1), bytes(&sha256(b"nobody.example")))]);
    assert_eq!(c.cred_mgmt(0x0A, 4, Some(no_rp), auth).0, 0x2E);
    assert_eq!(c.cred_mgmt(0x0A, 0x42, None, auth).0, 0x3E, "unknown subcommand");
}

#[test]
fn resident_key_capacity() {
    let mut c = Client::new(Arc::new(AutoPresence));
    for i in 0..1000u32 {
        let (status, _) = c.ctap2(0x01, Some(make_credential_params("example.com", &i.to_be_bytes(), "u", true, &[])));
        assert_eq!(status, 0);
    }
    let full = make_credential_params("example.com", b"one more", "u", true, &[]);
    assert_eq!(c.ctap2(0x01, Some(full)).0, 0x28, "KEY_STORE_FULL");
    // Replacing an existing user's credential and non-resident credentials still work.
    assert_eq!(c.ctap2(0x01, Some(make_credential_params("example.com", &7u32.to_be_bytes(), "u", true, &[]))).0, 0);
    assert_eq!(c.ctap2(0x01, Some(make_credential_params("example.com", b"x", "u", false, &[]))).0, 0);
}

// ---- large blobs ------------------------------------------------------------------

const MAX_FRAGMENT: usize = 1200 - 64;

impl Client {
    fn blob_read(&mut self, offset: usize, len: usize) -> (u8, Vec<u8>) {
        let (status, resp) = self.ctap2(0x0C, Some(map(vec![(int(1), int(len as i64)), (int(3), int(offset as i64))])));
        (status, resp.first().map(|_| get(&resp, 1).unwrap().as_bytes().unwrap().clone()).unwrap_or_default())
    }

    fn blob_read_all(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let (status, chunk) = self.blob_read(out.len(), MAX_FRAGMENT);
            assert_eq!(status, 0);
            let done = chunk.len() < MAX_FRAGMENT;
            out.extend(chunk);
            if done {
                return out;
            }
        }
    }

    fn blob_write_fragment(&mut self, offset: usize, fragment: &[u8], total: Option<usize>, token: Option<(PinProtocol, &[u8])>) -> u8 {
        let mut entries = vec![(int(2), bytes(fragment)), (int(3), int(offset as i64))];
        if let Some(t) = total {
            entries.push((int(4), int(t as i64)));
        }
        if let Some((p, token)) = token {
            let msg = [&[0xffu8; 32][..], &[0x0c, 0x00], &(offset as u32).to_le_bytes(), &sha256(fragment)].concat();
            entries.push((int(5), bytes(&p.authenticate(token, &msg))));
            entries.push((int(6), int(p.id())));
        }
        self.ctap2(0x0C, Some(map(entries))).0
    }

    /// Writes `serialized` in maximal fragments; returns the last status.
    fn blob_write_all(&mut self, serialized: &[u8], token: Option<(PinProtocol, &[u8])>) -> u8 {
        for (i, chunk) in serialized.chunks(MAX_FRAGMENT).enumerate() {
            let offset = i * MAX_FRAGMENT;
            let status = self.blob_write_fragment(offset, chunk, (offset == 0).then_some(serialized.len()), token);
            if status != 0 {
                return status;
            }
        }
        0
    }
}

/// CBOR array of `entries` byte strings || LEFT(SHA-256, 16).
fn serialized_blob_array(entries: &[&[u8]]) -> Vec<u8> {
    let mut data = Vec::new();
    ciborium::ser::into_writer(&Value::Array(entries.iter().map(|e| bytes(e)).collect()), &mut data).unwrap();
    let hash = sha256(&data);
    data.extend_from_slice(&hash[..16]);
    data
}

#[test]
fn large_blob_array_reads_and_writes() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let (_, info) = c.ctap2(0x04, None);
    assert_eq!(get_text(get(&info, 4).unwrap().as_map().unwrap(), "largeBlobs").unwrap().as_bool(), Some(true));
    assert_eq!(get(&info, 0x0B), Some(&int(4096)));
    assert_eq!(c.blob_read_all(), serialized_blob_array(&[]), "starts as the empty array");

    // A three-fragment write, read back in fragments.
    let big = vec![0x5Au8; 3000];
    let data = serialized_blob_array(&[&big, b"second"]);
    assert!(data.len() > 2 * MAX_FRAGMENT);
    assert_eq!(c.blob_write_all(&data, None), 0);
    assert_eq!(c.blob_read_all(), data);
    let (status, slice) = c.blob_read(100, 10);
    assert_eq!((status, slice.as_slice()), (0, &data[100..110]));
    assert_eq!(c.blob_read(data.len() + 1, 10).0, 0x02, "offset past the end");
    assert_eq!(c.blob_read(0, MAX_FRAGMENT + 1).0, 0x03, "fragment too long");

    // Protocol errors leave the stored array untouched.
    let next = serialized_blob_array(&[b"x"]);
    assert_eq!(c.blob_write_fragment(5, &next, None, None), 0x04, "no write in progress");
    assert_eq!(c.blob_write_fragment(0, &next, None, None), 0x02, "length missing at offset 0");
    assert_eq!(c.blob_write_fragment(0, &next[..4], Some(next.len()), None), 0);
    assert_eq!(c.blob_write_fragment(5, &next[4..], None, None), 0x04, "gap");
    assert_eq!(c.blob_write_fragment(4, &next[4..], Some(next.len()), None), 0x02, "length after offset 0");
    assert_eq!(c.blob_write_fragment(0, &[0; 10], Some(5000), None), 0x39, "too big");
    let mut corrupt = next.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(c.blob_write_all(&corrupt, None), 0x3C, "bad hash");
    assert_eq!(c.blob_read_all(), data);

    // Once a PIN is set, writes need it.
    let p = PinProtocol::V2;
    assert_eq!(c.set_pin(p, "1234"), 0);
    assert_eq!(c.blob_write_all(&next, None), 0x36);
    let token = c.pin_token(p, "1234").unwrap();
    assert_eq!(c.blob_write_all(&next, Some((p, &[0u8; 32]))), 0x33);
    assert_eq!(c.blob_write_all(&next, Some((p, &token))), 0);
    assert_eq!(c.blob_read_all(), next);

    assert_eq!(c.ctap2(0x07, None).0, 0);
    assert_eq!(c.blob_read_all(), serialized_blob_array(&[]), "reset clears it");
}

#[test]
fn large_blob_keys() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let lbk = || map(vec![(text("largeBlobKey"), Value::Bool(true))]);
    let non_resident = with_extensions(make_credential_params("example.com", b"u", "u", false, &[]), 6, lbk());
    assert_eq!(c.ctap2(0x01, Some(non_resident)).0, 0x2C, "resident keys only");
    let bad = with_extensions(make_credential_params("example.com", b"u", "u", true, &[]), 6, map(vec![(text("largeBlobKey"), Value::Bool(false))]));
    assert_eq!(c.ctap2(0x01, Some(bad)).0, 0x2C);

    let (status, resp) = c.ctap2(0x01, Some(with_extensions(make_credential_params("example.com", b"u", "u", true, &[]), 6, lbk())));
    assert_eq!(status, 0);
    let key = get(&resp, 5).unwrap().as_bytes().unwrap().clone();
    assert_eq!(key.len(), 32);
    let cred = parse_make_credential("example.com", &resp);
    assert_eq!(auth_data_extensions(get(&resp, 2).unwrap().as_bytes().unwrap()).1, None, "not an authData extension");

    let cdh = [0; 32];
    let (_, plain) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[])));
    assert!(get(&plain, 7).is_none(), "only when asked");
    let (status, resp) = c.ctap2(0x02, Some(with_extensions(get_assertion_params("example.com", &cdh, &[&cred.id]), 4, lbk())));
    assert_eq!(status, 0);
    assert_eq!(get(&resp, 7).unwrap().as_bytes().unwrap(), &key);

    // Credential management shows it too.
    let p = PinProtocol::V1;
    assert_eq!(c.set_pin(p, "1234"), 0);
    let token = c.pin_token(p, "1234").unwrap();
    let rp_hash = map(vec![(int(1), bytes(&sha256(b"example.com")))]);
    let (status, listed) = c.cred_mgmt(0x0A, 4, Some(rp_hash), Some((p, &token)));
    assert_eq!(status, 0);
    assert_eq!(get(&listed, 0x0B).unwrap().as_bytes().unwrap(), &key);
}

// ---- credBlob ---------------------------------------------------------------------

#[test]
fn cred_blob() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let (_, info) = c.ctap2(0x04, None);
    assert_eq!(get(&info, 0x0F), Some(&int(32)), "maxCredBlobLength");
    let create = |c: &mut Client, user: &[u8], rk: bool, ext: Value| {
        let (status, resp) = c.ctap2(0x01, Some(with_extensions(make_credential_params("example.com", user, "u", rk, &[]), 6, ext)));
        assert_eq!(status, 0);
        let ext = auth_data_extensions(get(&resp, 2).unwrap().as_bytes().unwrap()).1;
        (parse_make_credential("example.com", &resp), ext)
    };

    // Stored when it fits, for resident and non-resident credentials alike.
    let (resident, ext) = create(&mut c, b"r", true, map(vec![(text("credBlob"), bytes(b"resident blob"))]));
    assert_eq!(ext, Some(map(vec![(text("credBlob"), Value::Bool(true))])));
    let (plain, ext) = create(&mut c, b"p", false, map(vec![(text("credBlob"), bytes(&[9; 32]))]));
    assert_eq!(ext, Some(map(vec![(text("credBlob"), Value::Bool(true))])));
    // Too long: reported as not stored, but the credential is still created.
    let (too_long, ext) = create(&mut c, b"t", false, map(vec![(text("credBlob"), bytes(&[0; 33]))]));
    assert_eq!(ext, Some(map(vec![(text("credBlob"), Value::Bool(false))])));
    // Combined with hmac-secret, both outputs share one map.
    let (_, ext) = create(&mut c, b"h", false, map(vec![(text("hmac-secret"), Value::Bool(true)), (text("credBlob"), bytes(b"x"))]));
    assert_eq!(ext, Some(map(vec![(text("credBlob"), Value::Bool(true)), (text("hmac-secret"), Value::Bool(true))])));

    let cdh = [0; 32];
    let get_blob = |c: &mut Client, id: &[u8], ask: bool| {
        let mut params = get_assertion_params("example.com", &cdh, &[id]);
        if ask {
            params = with_extensions(params, 4, map(vec![(text("credBlob"), Value::Bool(true))]));
        }
        let (status, resp) = c.ctap2(0x02, Some(params));
        assert_eq!(status, 0);
        auth_data_extensions(get(&resp, 2).unwrap().as_bytes().unwrap())
    };
    assert_eq!(get_blob(&mut c, &resident.id, true), (0x81, Some(map(vec![(text("credBlob"), bytes(b"resident blob"))]))));
    assert_eq!(get_blob(&mut c, &plain.id, true).1, Some(map(vec![(text("credBlob"), bytes(&[9; 32]))])));
    assert_eq!(get_blob(&mut c, &too_long.id, true).1, Some(map(vec![(text("credBlob"), bytes(b""))])), "empty when none stored");
    assert_eq!(get_blob(&mut c, &resident.id, false), (0x01, None), "only when asked");

    let bad = with_extensions(make_credential_params("example.com", b"b", "u", true, &[]), 6, map(vec![(text("credBlob"), Value::Bool(true))]));
    assert_eq!(c.ctap2(0x01, Some(bad)).0, 0x11, "credBlob must be bytes");
}

// ---- Ed25519 ----------------------------------------------------------------------

fn make_credential_with_algs(rp: &str, user: &[u8], rk: bool, algs: &[i64]) -> Value {
    let Value::Map(mut entries) = make_credential_params(rp, user, "u", rk, &[]) else { unreachable!() };
    entries.retain(|(k, _)| k != &int(4));
    let params = algs.iter().map(|a| map(vec![(text("alg"), int(*a)), (text("type"), text("public-key"))]));
    entries.push((int(4), Value::Array(params.collect())));
    map(entries)
}

/// Returns (credential ID, Ed25519 public key) after checking the COSE key and the
/// self-attestation signature.
fn parse_ed25519_credential(resp: &[(Value, Value)]) -> (Vec<u8>, ed25519_dalek::VerifyingKey) {
    use ed25519_dalek::Verifier;
    let ad = get(resp, 2).unwrap().as_bytes().unwrap();
    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let id = ad[55..55 + id_len].to_vec();
    let mut rest = &ad[55 + id_len..];
    let cose: Value = ciborium::de::from_reader(&mut rest).unwrap();
    assert_eq!(
        cose,
        map(vec![(int(1), int(1)), (int(3), int(-8)), (int(-1), int(6)), (int(-2), get(cose.as_map().unwrap(), -2).unwrap().clone())]),
        "OKP / EdDSA / Ed25519 COSE key"
    );
    let x: [u8; 32] = get(cose.as_map().unwrap(), -2).unwrap().as_bytes().unwrap().as_slice().try_into().unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&x).unwrap();

    let att = get(resp, 3).unwrap().as_map().unwrap();
    assert_eq!(get_text(att, "alg"), Some(&int(-8)));
    let sig: [u8; 64] = get_text(att, "sig").unwrap().as_bytes().unwrap().as_slice().try_into().expect("raw 64-byte signature");
    key.verify(&[ad, &[0x11u8; 32][..]].concat(), &ed25519_dalek::Signature::from_bytes(&sig)).unwrap();
    (id, key)
}

#[test]
fn ed25519_credentials() {
    use ed25519_dalek::Verifier;
    let mut c = Client::new(Arc::new(AutoPresence));
    let (_, info) = c.ctap2(0x04, None);
    let algs: Vec<_> = get(&info, 0x0A).unwrap().as_array().unwrap().iter().map(|a| get_text(a.as_map().unwrap(), "alg").unwrap().clone()).collect();
    assert_eq!(algs, [int(-7), int(-8)]);

    // The RP's first supported preference wins.
    let (status, resp) = c.ctap2(0x01, Some(make_credential_with_algs("example.com", b"ed", true, &[-35, -8, -7])));
    assert_eq!(status, 0);
    let (id, key) = parse_ed25519_credential(&resp);
    let (_, resp) = c.ctap2(0x01, Some(make_credential_with_algs("example.com", b"ec", true, &[-7, -8])));
    let ec = parse_make_credential("example.com", &resp);

    for _ in 0..2 {
        let cdh = [0x42; 32];
        let (status, resp) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[&id])));
        assert_eq!(status, 0);
        let ad = get(&resp, 2).unwrap().as_bytes().unwrap();
        let sig: [u8; 64] = get(&resp, 3).unwrap().as_bytes().unwrap().as_slice().try_into().unwrap();
        key.verify(&[ad, &cdh[..]].concat(), &ed25519_dalek::Signature::from_bytes(&sig)).unwrap();
    }
    // Discovery returns both kinds, each signed with its own algorithm.
    let cdh = [0x43; 32];
    let (_, first) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[])));
    verify_assertion(&ec.key, &first, &cdh);
    let (_, second) = c.ctap2(0x08, None);
    let ad = get(&second, 2).unwrap().as_bytes().unwrap();
    let sig: [u8; 64] = get(&second, 3).unwrap().as_bytes().unwrap().as_slice().try_into().unwrap();
    key.verify(&[ad, &cdh[..]].concat(), &ed25519_dalek::Signature::from_bytes(&sig)).unwrap();

    // U2F can only produce P-256 signatures, so the Ed25519 credential is unknown to it.
    let app = sha256(b"example.com");
    let apdu = |kh: &[u8]| [&[0, 2, 0x07, 0, (65 + kh.len()) as u8][..], &[0; 32], &app, &[kh.len() as u8], kh].concat();
    assert_eq!(c.u2f(&apdu(&id)).1, 0x6A80);
    assert_eq!(c.u2f(&apdu(&ec.id)).1, 0x6985);

    // Credential management reports the Ed25519 COSE key.
    let p = PinProtocol::V2;
    assert_eq!(c.set_pin(p, "1234"), 0);
    let token = c.pin_token(p, "1234").unwrap();
    let (_, listed) = c.cred_mgmt(0x0A, 4, Some(map(vec![(int(1), bytes(&app))])), Some((p, &token)));
    let (_, next) = c.cred_mgmt(0x0A, 5, None, None);
    let ed_entry = if get(&listed, 7) == Some(&credential_descriptor(&id)) { listed } else { next };
    let cose = get(&ed_entry, 8).unwrap().as_map().unwrap();
    assert_eq!(get(cose, -2).unwrap().as_bytes().unwrap(), key.as_bytes());
}
